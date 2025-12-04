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

package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// contextKey is a private type for context keys to avoid collisions
type contextKey string

const (
	tenantIDContextKey contextKey = "tenant_id"
	userIDContextKey   contextKey = "user_id"
)

// maxRequestBodySize limits request body to 1MB to prevent memory exhaustion
const maxRequestBodySize = 1 << 20 // 1MB

// allowedOrigins defines the permitted CORS origins
var allowedOrigins = map[string]bool{
	"https://app.getaxonflow.com":      true,
	"https://staging.getaxonflow.com":  true,
	"https://demo.getaxonflow.com":     true,
	"https://customer.getaxonflow.com": true,
	"http://localhost:3000":            true,
	"http://localhost:8080":            true,
}

// PolicyAPIHandler handles HTTP requests for policy management
type PolicyAPIHandler struct {
	service PolicyServicer
}

// NewPolicyAPIHandler creates a new policy API handler
func NewPolicyAPIHandler(service PolicyServicer) *PolicyAPIHandler {
	return &PolicyAPIHandler{service: service}
}

// RegisterRoutes registers policy API routes with the provided mux
func (h *PolicyAPIHandler) RegisterRoutes(mux *http.ServeMux) {
	// CRUD endpoints
	mux.HandleFunc("/api/v1/policies", h.handlePolicies)
	mux.HandleFunc("/api/v1/policies/", h.handlePolicyByID)

	// Bulk operations
	mux.HandleFunc("/api/v1/policies/import", h.handleImport)
	mux.HandleFunc("/api/v1/policies/export", h.handleExport)
}

// handlePolicies handles GET (list) and POST (create) for /api/v1/policies
func (h *PolicyAPIHandler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listPolicies(w, r, tenantID)
	case http.MethodPost:
		h.createPolicy(w, r, tenantID)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handlePolicyByID handles individual policy operations
func (h *PolicyAPIHandler) handlePolicyByID(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	// Extract policy ID and subpath from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Policy ID is required")
		return
	}

	policyID := parts[0]

	// Validate policy ID is a valid UUID format
	if _, err := uuid.Parse(policyID); err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid policy ID format")
		return
	}

	subpath := ""
	if len(parts) > 1 {
		subpath = parts[1]
	}

	switch {
	case subpath == "test" && r.Method == http.MethodPost:
		h.testPolicy(w, r, tenantID, policyID)
	case subpath == "versions" && r.Method == http.MethodGet:
		h.getPolicyVersions(w, r, tenantID, policyID)
	case subpath == "" && r.Method == http.MethodGet:
		h.getPolicy(w, r, tenantID, policyID)
	case subpath == "" && r.Method == http.MethodPut:
		h.updatePolicy(w, r, tenantID, policyID)
	case subpath == "" && r.Method == http.MethodDelete:
		h.deletePolicy(w, r, tenantID, policyID)
	case r.Method == http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// createPolicy handles POST /api/v1/policies
func (h *PolicyAPIHandler) createPolicy(w http.ResponseWriter, r *http.Request, tenantID string) {
	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	userID := h.getUserID(r)
	policy, err := h.service.CreatePolicy(r.Context(), tenantID, &req, userID)
	if err != nil {
		if validationErr, ok := err.(*ValidationError); ok {
			h.writeValidationError(w, validationErr.Errors)
			return
		}
		// Log detailed error but return generic message
		log.Printf("[PolicyAPI] CreatePolicy error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create policy")
		return
	}

	h.writeJSON(w, http.StatusCreated, PolicyResponse{Policy: policy})
}

// listPolicies handles GET /api/v1/policies
func (h *PolicyAPIHandler) listPolicies(w http.ResponseWriter, r *http.Request, tenantID string) {
	params := ListPoliciesParams{
		Type:     r.URL.Query().Get("type"),
		Search:   r.URL.Query().Get("search"),
		SortBy:   r.URL.Query().Get("sort_by"),
		SortDir:  r.URL.Query().Get("sort_dir"),
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

	if enabledStr := r.URL.Query().Get("enabled"); enabledStr != "" {
		enabled := enabledStr == "true"
		params.Enabled = &enabled
	}

	response, err := h.service.ListPolicies(r.Context(), tenantID, params)
	if err != nil {
		log.Printf("[PolicyAPI] ListPolicies error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list policies")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getPolicy handles GET /api/v1/policies/{id}
func (h *PolicyAPIHandler) getPolicy(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	policy, err := h.service.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		log.Printf("[PolicyAPI] GetPolicy error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get policy")
		return
	}

	if policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy not found")
		return
	}

	h.writeJSON(w, http.StatusOK, PolicyResponse{Policy: policy})
}

// updatePolicy handles PUT /api/v1/policies/{id}
func (h *PolicyAPIHandler) updatePolicy(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	userID := h.getUserID(r)
	policy, err := h.service.UpdatePolicy(r.Context(), tenantID, policyID, &req, userID)
	if err != nil {
		if validationErr, ok := err.(*ValidationError); ok {
			h.writeValidationError(w, validationErr.Errors)
			return
		}
		log.Printf("[PolicyAPI] UpdatePolicy error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update policy")
		return
	}

	if policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy not found")
		return
	}

	h.writeJSON(w, http.StatusOK, PolicyResponse{Policy: policy})
}

// deletePolicy handles DELETE /api/v1/policies/{id}
func (h *PolicyAPIHandler) deletePolicy(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	userID := h.getUserID(r)

	// Check if policy exists first
	policy, err := h.service.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		log.Printf("[PolicyAPI] DeletePolicy check error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete policy")
		return
	}
	if policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy not found")
		return
	}

	if err := h.service.DeletePolicy(r.Context(), tenantID, policyID, userID); err != nil {
		log.Printf("[PolicyAPI] DeletePolicy error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete policy")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// testPolicy handles POST /api/v1/policies/{id}/test
func (h *PolicyAPIHandler) testPolicy(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req TestPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	if req.Query == "" {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Query is required for testing")
		return
	}

	response, err := h.service.TestPolicy(r.Context(), tenantID, policyID, &req)
	if err != nil {
		if err.Error() == "policy not found" {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy not found")
			return
		}
		log.Printf("[PolicyAPI] TestPolicy error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to test policy")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getPolicyVersions handles GET /api/v1/policies/{id}/versions
func (h *PolicyAPIHandler) getPolicyVersions(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	response, err := h.service.GetPolicyVersions(r.Context(), tenantID, policyID)
	if err != nil {
		log.Printf("[PolicyAPI] GetPolicyVersions error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get policy versions")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// maxImportBodySize limits import request body to 10MB for bulk operations
const maxImportBodySize = 10 << 20 // 10MB

// handleImport handles POST /api/v1/policies/import
func (h *PolicyAPIHandler) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
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

	// Limit request body size for imports (larger than single policy)
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBodySize)

	var req ImportPoliciesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	if len(req.Policies) == 0 {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "At least one policy is required")
		return
	}

	if len(req.Policies) > 100 {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Maximum 100 policies per import")
		return
	}

	userID := h.getUserID(r)
	response, err := h.service.ImportPolicies(r.Context(), tenantID, &req, userID)
	if err != nil {
		if validationErr, ok := err.(*ValidationError); ok {
			h.writeValidationError(w, validationErr.Errors)
			return
		}
		log.Printf("[PolicyAPI] ImportPolicies error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to import policies")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// handleExport handles GET /api/v1/policies/export
func (h *PolicyAPIHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
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

	response, err := h.service.ExportPolicies(r.Context(), tenantID)
	if err != nil {
		log.Printf("[PolicyAPI] ExportPolicies error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to export policies")
		return
	}

	// Set filename for download
	w.Header().Set("Content-Disposition", "attachment; filename=policies-export.json")
	h.writeJSON(w, http.StatusOK, response)
}

// Helper methods

// getTenantID extracts tenant ID from request
func (h *PolicyAPIHandler) getTenantID(r *http.Request) string {
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
func (h *PolicyAPIHandler) getUserID(r *http.Request) string {
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	if userID, ok := r.Context().Value("user_id").(string); ok {
		return userID
	}
	return "system"
}

// handleCORS sets CORS headers for OPTIONS requests with origin validation
func (h *PolicyAPIHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-User-ID")
	w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
	w.WriteHeader(http.StatusOK)
}

// writeJSON writes a JSON response
func (h *PolicyAPIHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func (h *PolicyAPIHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, PolicyAPIError{
		Error: PolicyAPIErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// writeValidationError writes a validation error response
func (h *PolicyAPIHandler) writeValidationError(w http.ResponseWriter, errors []PolicyFieldError) {
	h.writeJSON(w, http.StatusBadRequest, PolicyAPIError{
		Error: PolicyAPIErrorDetail{
			Code:    "VALIDATION_ERROR",
			Message: "Request validation failed",
			Details: errors,
		},
	})
}
