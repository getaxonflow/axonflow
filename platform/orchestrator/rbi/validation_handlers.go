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

// ModelValidationHandler handles HTTP requests for model validation operations.
type ModelValidationHandler struct {
	service ModelValidationService
}

// NewModelValidationHandler creates a new handler.
func NewModelValidationHandler(service ModelValidationService) *ModelValidationHandler {
	return &ModelValidationHandler{service: service}
}

// RegisterRoutes registers validation routes with the provided mux.
// Endpoints:
//   - POST   /api/v1/rbi/validations           - Create validation
//   - GET    /api/v1/rbi/validations           - List validations
//   - GET    /api/v1/rbi/validations/{id}      - Get validation
//   - PATCH  /api/v1/rbi/validations/{id}      - Update validation
//   - DELETE /api/v1/rbi/validations/{id}      - Delete validation
//   - POST   /api/v1/rbi/validations/{id}/findings - Add finding
//   - GET    /api/v1/rbi/systems/{id}/validations/latest - Get latest validation
func (h *ModelValidationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/rbi/validations", h.handleValidations)
	mux.HandleFunc("/api/v1/rbi/validations/", h.handleValidationByID)
}

// handleValidations handles POST/GET /api/v1/rbi/validations
func (h *ModelValidationHandler) handleValidations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createValidation(w, r)
	case http.MethodGet:
		h.listValidations(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleValidationByID handles requests for /api/v1/rbi/validations/{id}
func (h *ModelValidationHandler) handleValidationByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rbi/validations/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_ID", "Validation ID is required")
		return
	}

	validationID := parts[0]

	// Check for sub-routes
	if len(parts) > 1 {
		switch parts[1] {
		case "findings":
			if r.Method == http.MethodPost {
				h.addFinding(w, r, validationID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		h.getValidation(w, r, validationID)
	case http.MethodPatch:
		h.updateValidation(w, r, validationID)
	case http.MethodDelete:
		h.deleteValidation(w, r, validationID)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// createValidation handles POST /api/v1/rbi/validations
func (h *ModelValidationHandler) createValidation(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req CreateValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	validation, err := h.service.CreateValidation(r.Context(), orgID, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusCreated, validation)
}

// listValidations handles GET /api/v1/rbi/validations
func (h *ModelValidationHandler) listValidations(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	params := &ListValidationsParams{
		SystemID:       r.URL.Query().Get("system_id"),
		ValidationType: r.URL.Query().Get("validation_type"),
		ValidatorType:  r.URL.Query().Get("validator_type"),
		Recommendation: r.URL.Query().Get("recommendation"),
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

	validations, total, err := h.service.ListValidations(r.Context(), orgID, params)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := map[string]interface{}{
		"validations": validations,
		"total":       total,
		"limit":       params.Limit,
		"offset":      params.Offset,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getValidation handles GET /api/v1/rbi/validations/{id}
func (h *ModelValidationHandler) getValidation(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	validation, err := h.service.GetValidation(r.Context(), orgID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, validation)
}

// updateValidation handles PATCH /api/v1/rbi/validations/{id}
func (h *ModelValidationHandler) updateValidation(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req UpdateValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	validation, err := h.service.UpdateValidation(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, validation)
}

// deleteValidation handles DELETE /api/v1/rbi/validations/{id}
func (h *ModelValidationHandler) deleteValidation(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	if err := h.service.DeleteValidation(r.Context(), orgID, id); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// addFinding handles POST /api/v1/rbi/validations/{id}/findings
func (h *ModelValidationHandler) addFinding(w http.ResponseWriter, r *http.Request, validationID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var finding ValidationFinding
	if err := json.NewDecoder(r.Body).Decode(&finding); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	validation, err := h.service.AddFinding(r.Context(), orgID, validationID, &finding)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, validation)
}

// handleCORS handles OPTIONS requests.
func (h *ModelValidationHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Org-ID")
	w.WriteHeader(http.StatusNoContent)
}

// handleServiceError maps service errors to HTTP responses.
func (h *ModelValidationHandler) handleServiceError(w http.ResponseWriter, err error) {
	log.Printf("[RBI Validation] Error: %v", err)

	switch {
	case errors.Is(err, ErrValidationNotFound):
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Validation not found")
	case errors.Is(err, ErrSystemNotFound):
		h.writeError(w, http.StatusNotFound, "SYSTEM_NOT_FOUND", "AI system not found")
	case errors.Is(err, ErrInvalidInput):
		h.writeError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	default:
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred")
	}
}

// writeJSON writes a JSON response.
func (h *ModelValidationHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[RBI Validation] Error encoding JSON: %v", err)
	}
}

// writeError writes an error response.
func (h *ModelValidationHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
