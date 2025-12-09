// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// TemplateAPIHandler handles HTTP requests for template management
type TemplateAPIHandler struct {
	service TemplateServicer
}

// NewTemplateAPIHandler creates a new template API handler
func NewTemplateAPIHandler(service TemplateServicer) *TemplateAPIHandler {
	return &TemplateAPIHandler{service: service}
}

// HandleListTemplates handles GET /api/v1/templates - List templates by category
func (h *TemplateAPIHandler) HandleListTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w)
		return
	}

	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	params := ListTemplatesParams{
		Category: r.URL.Query().Get("category"),
		Search:   r.URL.Query().Get("search"),
		Tags:     r.URL.Query().Get("tags"),
		Page:     1,
		PageSize: 20,
	}

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			params.Page = page
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 && pageSize <= 100 {
			params.PageSize = pageSize
		}
	}

	if activeStr := r.URL.Query().Get("active"); activeStr != "" {
		active := activeStr == "true"
		params.Active = &active
	}

	if builtinStr := r.URL.Query().Get("builtin"); builtinStr != "" {
		builtin := builtinStr == "true"
		params.Builtin = &builtin
	}

	response, err := h.service.ListTemplates(r.Context(), params)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// HandleGetTemplate handles GET /api/v1/templates/{id} - Get single template
func (h *TemplateAPIHandler) HandleGetTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w)
		return
	}

	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	template, err := h.service.GetTemplate(r.Context(), templateID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	if template == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Template not found")
		return
	}

	h.writeJSON(w, http.StatusOK, TemplateResponse{Template: template})
}

// HandleApplyTemplate handles POST /api/v1/templates/{id}/apply - Apply template to create policy
func (h *TemplateAPIHandler) HandleApplyTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w)
		return
	}

	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	var req ApplyTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	userID := h.getUserID(r)
	response, err := h.service.ApplyTemplate(r.Context(), tenantID, templateID, &req, userID)
	if err != nil {
		if validationErr, ok := err.(*TemplateValidationError); ok {
			h.writeValidationError(w, validationErr.Errors)
			return
		}
		if err.Error() == "template not found" {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Template not found")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	h.writeJSON(w, http.StatusCreated, response)
}

// HandleGetCategories handles GET /api/v1/templates/categories - List all template categories
func (h *TemplateAPIHandler) HandleGetCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w)
		return
	}

	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	categories, err := h.service.GetCategories(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"categories": categories,
	})
}

// HandleGetUsageStats handles GET /api/v1/templates/stats - Get template usage statistics
func (h *TemplateAPIHandler) HandleGetUsageStats(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w)
		return
	}

	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	stats, err := h.service.GetUsageStats(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"stats": stats,
	})
}

// Helper methods

// getTenantID extracts tenant ID from request
func (h *TemplateAPIHandler) getTenantID(r *http.Request) string {
	// Try header first (for internal/service calls)
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}
	// Try from context (set by auth middleware)
	if tenantID, ok := r.Context().Value("tenant_id").(string); ok {
		return tenantID
	}
	return ""
}

// getUserID extracts user ID from request
func (h *TemplateAPIHandler) getUserID(r *http.Request) string {
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	if userID, ok := r.Context().Value("user_id").(string); ok {
		return userID
	}
	return "system"
}

// handleCORS sets CORS headers for OPTIONS requests
func (h *TemplateAPIHandler) handleCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-User-ID")
	w.WriteHeader(http.StatusOK)
}

// writeJSON writes a JSON response
func (h *TemplateAPIHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log encoding error but can't change response at this point
		_ = err
	}
}

// writeError writes an error response
func (h *TemplateAPIHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, TemplateAPIError{
		Error: TemplateAPIErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// writeValidationError writes a validation error response
func (h *TemplateAPIHandler) writeValidationError(w http.ResponseWriter, errors []TemplateFieldError) {
	h.writeJSON(w, http.StatusBadRequest, TemplateAPIError{
		Error: TemplateAPIErrorDetail{
			Code:    "VALIDATION_ERROR",
			Message: "Request validation failed",
			Details: errors,
		},
	})
}
