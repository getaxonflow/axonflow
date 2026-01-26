// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
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
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// DynamicPolicyAPIHandler handles HTTP requests for dynamic policy management.
// This provides the /api/v1/dynamic-policies endpoints for ADR-026 Single Entry Point.
// It delegates to the existing PolicyAPIHandler service but filters for dynamic policies.
type DynamicPolicyAPIHandler struct {
	service PolicyServicer
}

// NewDynamicPolicyAPIHandler creates a new dynamic policy API handler
func NewDynamicPolicyAPIHandler(service PolicyServicer) *DynamicPolicyAPIHandler {
	return &DynamicPolicyAPIHandler{service: service}
}

// RegisterRoutes registers dynamic policy API routes with the provided mux router
// These routes are for /api/v1/dynamic-policies (ADR-026: Single Entry Point)
func (h *DynamicPolicyAPIHandler) RegisterRoutes(r *mux.Router) {
	// List and Create
	r.HandleFunc("/api/v1/dynamic-policies", h.handleDynamicPolicies).Methods("GET", "POST", "OPTIONS")

	// Import/Export
	r.HandleFunc("/api/v1/dynamic-policies/import", h.handleImport).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/export", h.handleExport).Methods("GET", "OPTIONS")

	// Get effective policies
	r.HandleFunc("/api/v1/dynamic-policies/effective", h.handleEffective).Methods("GET", "OPTIONS")

	// Single policy operations (must come after specific routes)
	r.HandleFunc("/api/v1/dynamic-policies/{id}", h.handleDynamicPolicyByID).Methods("GET", "PUT", "DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/{id}/test", h.handleTest).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/{id}/versions", h.handleVersions).Methods("GET", "OPTIONS")

	log.Println("[DynamicPolicyAPI] Routes registered for /api/v1/dynamic-policies")
}

// handleDynamicPolicies handles GET (list) and POST (create) for /api/v1/dynamic-policies
func (h *DynamicPolicyAPIHandler) handleDynamicPolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listDynamicPolicies(w, r, tenantID)
	case http.MethodPost:
		h.createDynamicPolicy(w, r, tenantID)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// listDynamicPolicies handles GET /api/v1/dynamic-policies
// Filters to only return policies with category starting with "dynamic-"
func (h *DynamicPolicyAPIHandler) listDynamicPolicies(w http.ResponseWriter, r *http.Request, tenantID string) {
	params := ListPoliciesParams{
		Type:     r.URL.Query().Get("type"),
		Search:   r.URL.Query().Get("search"),
		SortBy:   r.URL.Query().Get("sort_by"),
		SortDir:  r.URL.Query().Get("sort_dir"),
		Page:     1,
		PageSize: 20,
	}

	// Always filter by dynamic category
	// If category is provided in query, validate it starts with "dynamic-"
	category := r.URL.Query().Get("category")
	if category != "" {
		if !strings.HasPrefix(category, "dynamic-") {
			h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Category must start with 'dynamic-' for this endpoint")
			return
		}
		params.Category = category
	} else {
		// Default: return all dynamic categories
		params.Category = "dynamic-%" // Service should handle this as LIKE pattern
	}

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			params.Page = page
		}
	}

	// Accept both limit (preferred) and page_size (deprecated) for backward compatibility
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			params.PageSize = limit
		}
	} else if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
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
		log.Printf("[DynamicPolicyAPI] ListDynamicPolicies error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list dynamic policies")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// createDynamicPolicy handles POST /api/v1/dynamic-policies
// Validates that the policy has a dynamic category
func (h *DynamicPolicyAPIHandler) createDynamicPolicy(w http.ResponseWriter, r *http.Request, tenantID string) {
	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	// Validate that category is a dynamic category
	if req.Category == "" {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Category is required and must start with 'dynamic-'")
		return
	}
	if !strings.HasPrefix(req.Category, "dynamic-") {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Category must start with 'dynamic-' (e.g., dynamic-risk, dynamic-cost)")
		return
	}

	userID := h.getUserID(r)
	policy, err := h.service.CreatePolicy(r.Context(), tenantID, &req, userID)
	if err != nil {
		if validationErr, ok := err.(*ValidationError); ok {
			h.writeValidationError(w, validationErr.Errors)
			return
		}
		if tierErr, ok := err.(*TierValidationError); ok {
			log.Printf("[DynamicPolicyAPI] CreateDynamicPolicy tier error for tenant %s: %v", tenantID, err)
			h.writeError(w, http.StatusForbidden, tierErr.Code, tierErr.Message)
			return
		}
		log.Printf("[DynamicPolicyAPI] CreateDynamicPolicy error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create dynamic policy")
		return
	}

	h.writeJSON(w, http.StatusCreated, PolicyResponse{Policy: policy})
}

// handleDynamicPolicyByID handles individual dynamic policy operations
func (h *DynamicPolicyAPIHandler) handleDynamicPolicyByID(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	// Extract policy ID from mux vars
	vars := mux.Vars(r)
	policyID := vars["id"]

	if policyID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Policy ID is required")
		return
	}

	// Validate policy ID is a valid UUID format
	if _, err := uuid.Parse(policyID); err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid policy ID format")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getDynamicPolicy(w, r, tenantID, policyID)
	case http.MethodPut:
		h.updateDynamicPolicy(w, r, tenantID, policyID)
	case http.MethodDelete:
		h.deleteDynamicPolicy(w, r, tenantID, policyID)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// getDynamicPolicy handles GET /api/v1/dynamic-policies/{id}
func (h *DynamicPolicyAPIHandler) getDynamicPolicy(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	policy, err := h.service.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		log.Printf("[DynamicPolicyAPI] GetDynamicPolicy error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get dynamic policy")
		return
	}

	if policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}

	// Verify this is actually a dynamic policy
	if !strings.HasPrefix(policy.Category, "dynamic-") {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy is not a dynamic policy")
		return
	}

	h.writeJSON(w, http.StatusOK, PolicyResponse{Policy: policy})
}

// updateDynamicPolicy handles PUT /api/v1/dynamic-policies/{id}
func (h *DynamicPolicyAPIHandler) updateDynamicPolicy(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	// First check that the existing policy is a dynamic policy
	existingPolicy, err := h.service.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		log.Printf("[DynamicPolicyAPI] UpdateDynamicPolicy check error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update dynamic policy")
		return
	}
	if existingPolicy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}
	if !strings.HasPrefix(existingPolicy.Category, "dynamic-") {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy is not a dynamic policy")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	// If category is being changed, validate it's still a dynamic category
	if req.Category != nil && !strings.HasPrefix(*req.Category, "dynamic-") {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Category must start with 'dynamic-'")
		return
	}

	userID := h.getUserID(r)
	policy, err := h.service.UpdatePolicy(r.Context(), tenantID, policyID, &req, userID)
	if err != nil {
		if validationErr, ok := err.(*ValidationError); ok {
			h.writeValidationError(w, validationErr.Errors)
			return
		}
		if tierErr, ok := err.(*TierValidationError); ok {
			log.Printf("[DynamicPolicyAPI] UpdateDynamicPolicy tier error for tenant %s, policy %s: %v", tenantID, policyID, err)
			h.writeError(w, http.StatusForbidden, tierErr.Code, tierErr.Message)
			return
		}
		log.Printf("[DynamicPolicyAPI] UpdateDynamicPolicy error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update dynamic policy")
		return
	}

	if policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}

	h.writeJSON(w, http.StatusOK, PolicyResponse{Policy: policy})
}

// deleteDynamicPolicy handles DELETE /api/v1/dynamic-policies/{id}
func (h *DynamicPolicyAPIHandler) deleteDynamicPolicy(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	// First check that the existing policy is a dynamic policy
	existingPolicy, err := h.service.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		log.Printf("[DynamicPolicyAPI] DeleteDynamicPolicy check error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete dynamic policy")
		return
	}
	if existingPolicy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}
	if !strings.HasPrefix(existingPolicy.Category, "dynamic-") {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy is not a dynamic policy")
		return
	}

	userID := h.getUserID(r)
	if err := h.service.DeletePolicy(r.Context(), tenantID, policyID, userID); err != nil {
		if tierErr, ok := err.(*TierValidationError); ok {
			log.Printf("[DynamicPolicyAPI] DeleteDynamicPolicy tier error for tenant %s, policy %s: %v", tenantID, policyID, err)
			h.writeError(w, http.StatusForbidden, tierErr.Code, tierErr.Message)
			return
		}
		log.Printf("[DynamicPolicyAPI] DeleteDynamicPolicy error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete dynamic policy")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleTest handles POST /api/v1/dynamic-policies/{id}/test
func (h *DynamicPolicyAPIHandler) handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	vars := mux.Vars(r)
	policyID := vars["id"]

	if _, err := uuid.Parse(policyID); err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid policy ID format")
		return
	}

	// Verify this is a dynamic policy
	policy, err := h.service.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil || policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}
	if !strings.HasPrefix(policy.Category, "dynamic-") {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy is not a dynamic policy")
		return
	}

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
		log.Printf("[DynamicPolicyAPI] TestPolicy error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to test dynamic policy")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// handleVersions handles GET /api/v1/dynamic-policies/{id}/versions
func (h *DynamicPolicyAPIHandler) handleVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	vars := mux.Vars(r)
	policyID := vars["id"]

	if _, err := uuid.Parse(policyID); err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid policy ID format")
		return
	}

	// Verify this is a dynamic policy
	policy, err := h.service.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil || policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}
	if !strings.HasPrefix(policy.Category, "dynamic-") {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy is not a dynamic policy")
		return
	}

	response, err := h.service.GetPolicyVersions(r.Context(), tenantID, policyID)
	if err != nil {
		log.Printf("[DynamicPolicyAPI] GetPolicyVersions error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get policy versions")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// handleImport handles POST /api/v1/dynamic-policies/import
func (h *DynamicPolicyAPIHandler) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

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

	// Validate all policies have dynamic categories
	for i, policy := range req.Policies {
		if !strings.HasPrefix(policy.Category, "dynamic-") {
			h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				"Policy at index "+strconv.Itoa(i)+" has invalid category: must start with 'dynamic-'")
			return
		}
	}

	userID := h.getUserID(r)
	response, err := h.service.ImportPolicies(r.Context(), tenantID, &req, userID)
	if err != nil {
		if validationErr, ok := err.(*ValidationError); ok {
			h.writeValidationError(w, validationErr.Errors)
			return
		}
		log.Printf("[DynamicPolicyAPI] ImportPolicies error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to import dynamic policies")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// handleExport handles GET /api/v1/dynamic-policies/export
func (h *DynamicPolicyAPIHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	// Export only dynamic policies - the service will need to filter
	// For now, we'll get all and filter client-side (or update service to accept category filter)
	response, err := h.service.ExportPolicies(r.Context(), tenantID)
	if err != nil {
		log.Printf("[DynamicPolicyAPI] ExportPolicies error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to export dynamic policies")
		return
	}

	// Filter to only include dynamic policies in the export
	if response != nil {
		filtered := make([]PolicyResource, 0)
		for _, p := range response.Policies {
			if strings.HasPrefix(p.Category, "dynamic-") {
				filtered = append(filtered, p)
			}
		}
		response.Policies = filtered
	}

	h.writeJSON(w, http.StatusOK, response)
}

// handleEffective handles GET /api/v1/dynamic-policies/effective
func (h *DynamicPolicyAPIHandler) handleEffective(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	// Get effective policies (enabled, sorted by priority)
	params := ListPoliciesParams{
		Category: "dynamic-%",
		Page:     1,
		PageSize: 100, // Return all effective policies
		SortBy:   "priority",
		SortDir:  "asc",
	}
	enabled := true
	params.Enabled = &enabled

	response, err := h.service.ListPolicies(r.Context(), tenantID, params)
	if err != nil {
		log.Printf("[DynamicPolicyAPI] GetEffectivePolicies error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get effective dynamic policies")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// Helper methods (same pattern as PolicyAPIHandler)

func (h *DynamicPolicyAPIHandler) getTenantID(r *http.Request) string {
	// Check X-Tenant-ID header first
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}
	// Fallback to X-Org-ID for backward compatibility
	return r.Header.Get("X-Org-ID")
}

func (h *DynamicPolicyAPIHandler) getUserID(r *http.Request) string {
	return r.Header.Get("X-User-ID")
}

func (h *DynamicPolicyAPIHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[DynamicPolicyAPI] Error encoding JSON response: %v", err)
	}
}

func (h *DynamicPolicyAPIHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func (h *DynamicPolicyAPIHandler) writeValidationError(w http.ResponseWriter, errors []PolicyFieldError) {
	h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    "VALIDATION_ERROR",
			"message": "Validation failed",
			"fields":  errors,
		},
	})
}

func (h *DynamicPolicyAPIHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-User-ID, X-Org-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}
