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
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"axonflow/platform/shared/policypath"
)

// isValidDynamicPolicyCategory returns true if the category is valid for the
// /api/v1/dynamic-policies endpoint. Accepts both "dynamic-*" and "media-*" prefixes.
func isValidDynamicPolicyCategory(category string) bool {
	return strings.HasPrefix(category, "dynamic-") || strings.HasPrefix(category, "media-")
}

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

// RegisterRoutes registers the tenant policy API routes under BOTH the legacy
// /api/v1/dynamic-policies prefix and the #1431 successor
// /api/v1/tenant-policies (ADR-026: Single Entry Point).
//
// EDITION (HARD RULE 11): a rename, not a capability. Both prefixes are
// registered by this one function at this one call site, so the successor
// inherits the caller's edition gating exactly; there is no second condition
// to drift, and the orchestrator's authn (requireInternalProxyAuth) is a
// wrapper around the whole mux with a path exemption map that names neither
// prefix, so both are equally authenticated.
//
// WHY TWO LITERAL BLOCKS AND NOT A LOOP OVER A PREFIX PAIR. The first draft of
// this function built each path as policypath.TenantPolicies+suffix. That is
// drift-proof and it is WRONG here, because the customer-portal's census
// (TestEveryOrchestratorRouteIsClassifiedForTheProxy, and the gate census in
// policy_route_gate_coverage_test.go) walks go/ast over THIS package to answer
// "which orchestrator routes can a portal session reach, and is each one
// classified?" - and a path that is not a string literal is a path that census
// cannot see. Both tests fail loudly rather than skipping, which is how the
// draft was caught. A concatenated constant would have made eight
// policy-mutating routes invisible to the guard that exists to stop exactly
// that. So: literals here, and TestTenantPolicyAliasIsCompleteAndSymmetric
// re-derives both blocks and fails if a route exists on one prefix and not the
// other.
//
// The deprecation stamp is applied ONLY to the legacy block, by wrapping the
// shared handler value. It is not a router-level middleware because these
// routes sit on the orchestrator's ROOT router, where a middleware would run
// on every orchestrator route.
//
// The consequence, stated so it is not discovered later: because the stamp is
// INSIDE the handler, a request refused before the handler runs carries no
// signal. requireInternalProxyAuth wraps the whole mux (run.go), so an
// unauthenticated caller gets 403 with no Deprecation header. That is the
// opposite of the agent, where the stamp is subrouter middleware mounted ahead
// of apiAuthMiddleware and therefore rides the 401. Neither is wrong - a
// deprecation notice is not something to hand an unauthenticated caller on
// this plane - but the two planes differ, and the public docs say to sample a
// SUCCESSFUL response rather than an error one for exactly this reason.
func (h *DynamicPolicyAPIHandler) RegisterRoutes(r *mux.Router) {
	// ---- deprecated: /api/v1/dynamic-policies -----------------------------
	// Same handler values as the successor block below, wrapped so the
	// response carries Deprecation + Link. Order matters and is preserved:
	// the literal suffixes must precede "/{id}" or gorilla/mux matches
	// "import" as an id.
	r.HandleFunc("/api/v1/dynamic-policies", policypath.DeprecateLegacyFunc(h.handleDynamicPolicies)).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/import", policypath.DeprecateLegacyFunc(h.handleImport)).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/export", policypath.DeprecateLegacyFunc(h.handleExport)).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/effective", policypath.DeprecateLegacyFunc(h.handleEffective)).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/{id}", policypath.DeprecateLegacyFunc(h.handleDynamicPolicyByID)).Methods("GET", "PUT", "DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/{id}/test", policypath.DeprecateLegacyFunc(h.handleTest)).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/dynamic-policies/{id}/versions", policypath.DeprecateLegacyFunc(h.handleVersions)).Methods("GET", "OPTIONS")

	// ---- current: /api/v1/tenant-policies (#1431) -------------------------
	// Line-for-line the block above, same handler values, no stamp.
	r.HandleFunc("/api/v1/tenant-policies", h.handleDynamicPolicies).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/tenant-policies/import", h.handleImport).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/tenant-policies/export", h.handleExport).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/tenant-policies/effective", h.handleEffective).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/tenant-policies/{id}", h.handleDynamicPolicyByID).Methods("GET", "PUT", "DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/tenant-policies/{id}/test", h.handleTest).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/tenant-policies/{id}/versions", h.handleVersions).Methods("GET", "OPTIONS")

	log.Printf("[TenantPolicyAPI] Routes registered on %s (deprecated) and %s",
		policypath.LegacyTenantPolicies, policypath.TenantPolicies)
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

	// Filter by category — accepts both "dynamic-*" and "media-*" prefixes
	category := r.URL.Query().Get("category")
	if category != "" {
		if !isValidDynamicPolicyCategory(category) {
			h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Category must start with 'dynamic-' or 'media-' for this endpoint")
			return
		}
		params.Category = category
	} else if params.Type == "media" {
		// If type=media, filter to media categories
		params.Category = "media-%"
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

	response, err := h.service.ListPolicies(r.Context(), tenantID, h.getOrgID(r), params)
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

	// Validate that category is a dynamic or media category
	if req.Category == "" {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Category is required and must start with 'dynamic-' or 'media-'")
		return
	}
	if !isValidDynamicPolicyCategory(req.Category) {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Category must start with 'dynamic-' or 'media-' (e.g., dynamic-risk, media-safety)")
		return
	}

	userID := h.getUserID(r)
	policy, err := h.service.CreatePolicy(r.Context(), tenantID, strings.TrimSpace(r.Header.Get("X-Org-ID")), &req, userID)
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

	// Validate policy ID format (UUID or system policy prefix)
	if !isValidPolicyID(policyID) {
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
	policy, err := h.service.GetPolicy(r.Context(), tenantID, h.getOrgID(r), policyID)
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
	if !isValidDynamicPolicyCategory(policy.Category) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy is not a dynamic policy")
		return
	}

	h.writeJSON(w, http.StatusOK, PolicyResponse{Policy: policy})
}

// updateDynamicPolicy handles PUT /api/v1/dynamic-policies/{id}
func (h *DynamicPolicyAPIHandler) updateDynamicPolicy(w http.ResponseWriter, r *http.Request, tenantID, policyID string) {
	// First check that the existing policy is a dynamic policy
	existingPolicy, err := h.service.GetPolicy(r.Context(), tenantID, h.getOrgID(r), policyID)
	if err != nil {
		log.Printf("[DynamicPolicyAPI] UpdateDynamicPolicy check error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update dynamic policy")
		return
	}
	if existingPolicy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}
	if !isValidDynamicPolicyCategory(existingPolicy.Category) {
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

	// If category is being changed, validate it's still a valid category
	if req.Category != nil && !isValidDynamicPolicyCategory(*req.Category) {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Category must start with 'dynamic-' or 'media-'")
		return
	}

	userID := h.getUserID(r)
	policy, err := h.service.UpdatePolicy(r.Context(), tenantID, h.getOrgID(r), policyID, &req, userID)
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
	existingPolicy, err := h.service.GetPolicy(r.Context(), tenantID, h.getOrgID(r), policyID)
	if err != nil {
		log.Printf("[DynamicPolicyAPI] DeleteDynamicPolicy check error for tenant %s, policy %s: %v", tenantID, policyID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete dynamic policy")
		return
	}
	if existingPolicy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}
	if !isValidDynamicPolicyCategory(existingPolicy.Category) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Policy is not a dynamic policy")
		return
	}

	userID := h.getUserID(r)
	if err := h.service.DeletePolicy(r.Context(), tenantID, h.getOrgID(r), policyID, userID); err != nil {
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

	if !isValidPolicyID(policyID) {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid policy ID format")
		return
	}

	// Verify this is a dynamic policy
	policy, err := h.service.GetPolicy(r.Context(), tenantID, h.getOrgID(r), policyID)
	if err != nil || policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}
	if !isValidDynamicPolicyCategory(policy.Category) {
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

	response, err := h.service.TestPolicy(r.Context(), tenantID, h.getOrgID(r), policyID, &req)
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

	if !isValidPolicyID(policyID) {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid policy ID format")
		return
	}

	// Verify this is a dynamic policy
	policy, err := h.service.GetPolicy(r.Context(), tenantID, h.getOrgID(r), policyID)
	if err != nil || policy == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Dynamic policy not found")
		return
	}
	if !isValidDynamicPolicyCategory(policy.Category) {
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

	// Decision 5 (#3490): a bulk import WRITES policies, and org_id is what
	// selects them. Refused rather than defaulted to the tenant, for the same
	// reason single-policy creation refuses: a default would stamp every
	// imported row with the Basic-auth username, and on a deployment whose
	// licence org differs from that string the import would report success
	// while enforcing on nobody. The /api/v1/dynamic-policies prefix is agent-proxied, so the gateway
	// Sets X-Org-ID from the validated licence on the real path.
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "ORG_REQUIRED",
			"Missing organisation: imported policies are selected by their organisation. Send X-Org-ID.")
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

	// Validate all policies have valid categories (dynamic-* or media-*)
	for i, policy := range req.Policies {
		if !isValidDynamicPolicyCategory(policy.Category) {
			h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				"Policy at index "+strconv.Itoa(i)+" has invalid category: must start with 'dynamic-' or 'media-'")
			return
		}
	}

	userID := h.getUserID(r)
	response, err := h.service.ImportPolicies(r.Context(), tenantID, orgID, &req, userID)
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
	response, err := h.service.ExportPolicies(r.Context(), tenantID, h.getOrgID(r))
	if err != nil {
		log.Printf("[DynamicPolicyAPI] ExportPolicies error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to export dynamic policies")
		return
	}

	// Filter to only include dynamic/media policies in the export
	if response != nil {
		filtered := make([]PolicyResource, 0)
		for _, p := range response.Policies {
			if isValidDynamicPolicyCategory(p.Category) {
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
	// Do not filter by category — return both dynamic-* and media-* policies
	params := ListPoliciesParams{
		Page:     1,
		PageSize: 100, // Return all effective policies
		SortBy:   "priority",
		SortDir:  "asc",
	}
	enabled := true
	params.Enabled = &enabled

	response, err := h.service.ListPolicies(r.Context(), tenantID, h.getOrgID(r), params)
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

// getOrgID extracts the organisation from the gateway-Set header.
//
// Header only and trimmed, matching PolicyAPIHandler.getOrgID: the agent Sets
// (not Adds) X-Org-ID from the cryptographically validated licence payload, so
// a client-supplied value is overwritten before this is read, and there is no
// context fallback to resolve to "" behind an operator's back.
func (h *DynamicPolicyAPIHandler) getOrgID(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Org-ID"))
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

// isValidPolicyID accepts UUIDs, system policy IDs (sys_* prefix), and the
// legacy snake_case identifiers used by migration 010_policy_tables.sql
// (e.g. "sensitive_data_control") that pre-date the sys_* convention.
// Without the legacy form every Test / Edit / Delete / Versions action on
// those policies 400s with "Invalid policy ID format".
//
// The pattern is intentionally narrow — letters, digits, underscores, hyphens —
// to keep the validator a defense-in-depth check; the actual SQL lookups are
// parameterized.
var legacyPolicyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,127}$`)

func isValidPolicyID(id string) bool {
	if _, err := uuid.Parse(id); err == nil {
		return true
	}
	if strings.HasPrefix(id, "sys_") {
		return true
	}
	return legacyPolicyIDPattern.MatchString(id)
}
