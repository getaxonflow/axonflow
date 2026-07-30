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

// AIIncidentHandler handles HTTP requests for AI incident operations.
type AIIncidentHandler struct {
	service AIIncidentService
}

// NewAIIncidentHandler creates a new handler.
func NewAIIncidentHandler(service AIIncidentService) *AIIncidentHandler {
	return &AIIncidentHandler{service: service}
}

// RegisterRoutes registers incident routes with the provided mux.
// Endpoints:
//   - POST   /api/v1/rbi/incidents              - Create incident
//   - GET    /api/v1/rbi/incidents              - List incidents
//   - GET    /api/v1/rbi/incidents/open         - Get open incidents
//   - GET    /api/v1/rbi/incidents/pending-board - Get pending board notifications
//   - GET    /api/v1/rbi/incidents/pending-rbi  - Get pending RBI notifications
//   - GET    /api/v1/rbi/incidents/{id}         - Get incident
//   - PATCH  /api/v1/rbi/incidents/{id}         - Update incident
//   - DELETE /api/v1/rbi/incidents/{id}         - Delete incident
//   - POST   /api/v1/rbi/incidents/{id}/status  - Update status
//   - POST   /api/v1/rbi/incidents/{id}/actions - Add remediation action
//   - PATCH  /api/v1/rbi/incidents/{id}/actions/{actionId} - Update action
//   - POST   /api/v1/rbi/incidents/{id}/notify/board - Record board notification
//   - POST   /api/v1/rbi/incidents/{id}/notify/rbi   - Record RBI notification
func (h *AIIncidentHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/rbi/incidents", h.handleIncidents)
	mux.HandleFunc("/api/v1/rbi/incidents/", h.handleIncidentRoutes)
}

// handleIncidents handles POST/GET /api/v1/rbi/incidents
func (h *AIIncidentHandler) handleIncidents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createIncident(w, r)
	case http.MethodGet:
		h.listIncidents(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleIncidentRoutes handles requests for /api/v1/rbi/incidents/...
func (h *AIIncidentHandler) handleIncidentRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rbi/incidents/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid path")
		return
	}

	// Handle special routes
	switch parts[0] {
	case "open":
		if r.Method == http.MethodGet {
			h.getOpenIncidents(w, r)
		} else if r.Method == http.MethodOptions {
			h.handleCORS(w, r)
		} else {
			h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
		return
	case "pending-board":
		if r.Method == http.MethodGet {
			h.getPendingBoardNotifications(w, r)
		} else if r.Method == http.MethodOptions {
			h.handleCORS(w, r)
		} else {
			h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
		return
	case "pending-rbi":
		if r.Method == http.MethodGet {
			h.getPendingRBINotifications(w, r)
		} else if r.Method == http.MethodOptions {
			h.handleCORS(w, r)
		} else {
			h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
		return
	}

	incidentID := parts[0]

	// Handle sub-routes
	if len(parts) > 1 {
		switch parts[1] {
		case "status":
			if r.Method == http.MethodPost {
				h.updateStatus(w, r, incidentID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		case "actions":
			if len(parts) == 2 {
				if r.Method == http.MethodPost {
					h.addRemediationAction(w, r, incidentID)
				} else if r.Method == http.MethodOptions {
					h.handleCORS(w, r)
				} else {
					h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
				}
			} else if len(parts) == 3 {
				actionID := parts[2]
				if r.Method == http.MethodPatch {
					h.updateRemediationAction(w, r, incidentID, actionID)
				} else if r.Method == http.MethodOptions {
					h.handleCORS(w, r)
				} else {
					h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
				}
			}
			return
		case "notify":
			if len(parts) > 2 {
				switch parts[2] {
				case "board":
					if r.Method == http.MethodPost {
						h.recordBoardNotification(w, r, incidentID)
					} else if r.Method == http.MethodOptions {
						h.handleCORS(w, r)
					} else {
						h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
					}
					return
				case "rbi":
					if r.Method == http.MethodPost {
						h.recordRBINotification(w, r, incidentID)
					} else if r.Method == http.MethodOptions {
						h.handleCORS(w, r)
					} else {
						h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
					}
					return
				}
			}
		}
	}

	// Handle basic CRUD for incident
	switch r.Method {
	case http.MethodGet:
		h.getIncident(w, r, incidentID)
	case http.MethodPatch:
		h.updateIncident(w, r, incidentID)
	case http.MethodDelete:
		h.deleteIncident(w, r, incidentID)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// createIncident handles POST /api/v1/rbi/incidents
func (h *AIIncidentHandler) createIncident(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req CreateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	incident, err := h.service.CreateIncident(r.Context(), orgID, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusCreated, incident)
}

// listIncidents handles GET /api/v1/rbi/incidents
func (h *AIIncidentHandler) listIncidents(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	params := &ListIncidentsParams{
		SystemID:     r.URL.Query().Get("system_id"),
		IncidentType: r.URL.Query().Get("incident_type"),
		Severity:     r.URL.Query().Get("severity"),
		Status:       r.URL.Query().Get("status"),
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
	if boardNotifiedStr := r.URL.Query().Get("board_notified"); boardNotifiedStr != "" {
		val := boardNotifiedStr == "true"
		params.BoardNotified = &val
	}
	if rbiNotifiedStr := r.URL.Query().Get("rbi_notified"); rbiNotifiedStr != "" {
		val := rbiNotifiedStr == "true"
		params.RBINotified = &val
	}

	incidents, total, err := h.service.ListIncidents(r.Context(), orgID, params)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := map[string]interface{}{
		"incidents": incidents,
		"total":     total,
		"limit":     params.Limit,
		"offset":    params.Offset,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getIncident handles GET /api/v1/rbi/incidents/{id}
func (h *AIIncidentHandler) getIncident(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	incident, err := h.service.GetIncident(r.Context(), orgID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, incident)
}

// updateIncident handles PATCH /api/v1/rbi/incidents/{id}
func (h *AIIncidentHandler) updateIncident(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req UpdateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	incident, err := h.service.UpdateIncident(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, incident)
}

// deleteIncident handles DELETE /api/v1/rbi/incidents/{id}
func (h *AIIncidentHandler) deleteIncident(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	if err := h.service.DeleteIncident(r.Context(), orgID, id); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// updateStatus handles POST /api/v1/rbi/incidents/{id}/status
func (h *AIIncidentHandler) updateStatus(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req struct {
		Status     string `json:"status"`
		Resolution string `json:"resolution,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	incident, err := h.service.UpdateStatus(r.Context(), orgID, id, IncidentStatus(req.Status), req.Resolution)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, incident)
}

// addRemediationAction handles POST /api/v1/rbi/incidents/{id}/actions
func (h *AIIncidentHandler) addRemediationAction(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var action RemediationAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	incident, err := h.service.AddRemediationAction(r.Context(), orgID, id, &action)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, incident)
}

// updateRemediationAction handles PATCH /api/v1/rbi/incidents/{id}/actions/{actionId}
func (h *AIIncidentHandler) updateRemediationAction(w http.ResponseWriter, r *http.Request, id, actionID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req UpdateRemediationActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	incident, err := h.service.UpdateRemediationAction(r.Context(), orgID, id, actionID, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, incident)
}

// recordBoardNotification handles POST /api/v1/rbi/incidents/{id}/notify/board
func (h *AIIncidentHandler) recordBoardNotification(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req RecordNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	incident, err := h.service.RecordBoardNotification(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, incident)
}

// recordRBINotification handles POST /api/v1/rbi/incidents/{id}/notify/rbi
func (h *AIIncidentHandler) recordRBINotification(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req RecordNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	incident, err := h.service.RecordRBINotification(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, incident)
}

// getOpenIncidents handles GET /api/v1/rbi/incidents/open
func (h *AIIncidentHandler) getOpenIncidents(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	incidents, err := h.service.GetOpenIncidents(r.Context(), orgID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"incidents": incidents,
		"total":     len(incidents),
	})
}

// getPendingBoardNotifications handles GET /api/v1/rbi/incidents/pending-board
func (h *AIIncidentHandler) getPendingBoardNotifications(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	incidents, err := h.service.GetPendingBoardNotifications(r.Context(), orgID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"incidents": incidents,
		"total":     len(incidents),
	})
}

// getPendingRBINotifications handles GET /api/v1/rbi/incidents/pending-rbi
func (h *AIIncidentHandler) getPendingRBINotifications(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	incidents, err := h.service.GetPendingRBINotifications(r.Context(), orgID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"incidents": incidents,
		"total":     len(incidents),
	})
}

// handleCORS handles OPTIONS requests.
func (h *AIIncidentHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Org-ID")
	w.WriteHeader(http.StatusNoContent)
}

// handleServiceError maps service errors to HTTP responses.
func (h *AIIncidentHandler) handleServiceError(w http.ResponseWriter, err error) {
	log.Printf("[RBI Incident] Error: %v", err)

	switch {
	case errors.Is(err, ErrIncidentNotFound):
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Incident not found")
	case errors.Is(err, ErrSystemNotFound):
		h.writeError(w, http.StatusNotFound, "SYSTEM_NOT_FOUND", "AI system not found")
	case errors.Is(err, ErrInvalidInput):
		h.writeError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	default:
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred")
	}
}

// writeJSON writes a JSON response.
func (h *AIIncidentHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[RBI Incident] Error encoding JSON: %v", err)
	}
}

// writeError writes an error response.
func (h *AIIncidentHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
