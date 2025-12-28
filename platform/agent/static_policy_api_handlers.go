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

// Package agent provides the AxonFlow Agent service.
//
// This file implements the Static Policies REST API for ADR-018: Unified Policy Management.
// Static policies are pattern-based enforcement rules (PII detection, SQL injection blocking)
// that are stored in the static_policies table and evaluated by the Agent.
//
// API Endpoints:
//   - GET    /api/v1/static-policies           - List policies with filtering
//   - POST   /api/v1/static-policies           - Create a new policy
//   - GET    /api/v1/static-policies/{id}      - Get policy by ID
//   - PUT    /api/v1/static-policies/{id}      - Update policy
//   - DELETE /api/v1/static-policies/{id}      - Soft delete policy
//   - PATCH  /api/v1/static-policies/{id}      - Toggle enabled status
//   - GET    /api/v1/static-policies/effective - Get effective policies with overrides
//   - POST   /api/v1/static-policies/test      - Test a pattern against input
//   - GET    /api/v1/static-policies/{id}/versions - Get version history
//   - POST   /api/v1/static-policies/{id}/override - Create override (Enterprise)
//   - DELETE /api/v1/static-policies/{id}/override - Delete override (Enterprise)
package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// Note: StaticPolicy, CreateStaticPolicyRequest, UpdateStaticPolicyRequest, and related types
// are defined in policy_types.go with enhanced fields for tier hierarchy support (ADR-020).

// StaticPolicyAPIHandler handles static policy API requests.
// It uses StaticPolicyRepository and PolicyOverrideRepository for database operations.
type StaticPolicyAPIHandler struct {
	db           *sql.DB
	policyRepo   *StaticPolicyRepository
	overrideRepo *PolicyOverrideRepository
}

// NewStaticPolicyAPIHandler creates a new handler for static policy API.
func NewStaticPolicyAPIHandler(db *sql.DB) *StaticPolicyAPIHandler {
	return &StaticPolicyAPIHandler{
		db:           db,
		policyRepo:   NewStaticPolicyRepository(db),
		overrideRepo: NewPolicyOverrideRepository(db),
	}
}

// RegisterStaticPolicyHandlers registers the static policy API routes.
func RegisterStaticPolicyHandlers(router *mux.Router, db *sql.DB) {
	if db == nil {
		log.Println("⚠️ Database not available - Static Policy API disabled")
		return
	}

	handler := NewStaticPolicyAPIHandler(db)

	// List and effective endpoints (must come before {id} routes)
	router.HandleFunc("/api/v1/static-policies", handler.HandleListStaticPolicies).Methods("GET")
	router.HandleFunc("/api/v1/static-policies", handler.HandleCreateStaticPolicy).Methods("POST")
	router.HandleFunc("/api/v1/static-policies/effective", handler.HandleGetEffectivePolicies).Methods("GET")
	router.HandleFunc("/api/v1/static-policies/test", handler.HandleTestPattern).Methods("POST")

	// Single policy operations
	router.HandleFunc("/api/v1/static-policies/{id}", handler.HandleGetStaticPolicy).Methods("GET")
	router.HandleFunc("/api/v1/static-policies/{id}", handler.HandleUpdateStaticPolicy).Methods("PUT")
	router.HandleFunc("/api/v1/static-policies/{id}", handler.HandleDeleteStaticPolicy).Methods("DELETE")
	router.HandleFunc("/api/v1/static-policies/{id}", handler.HandleTogglePolicy).Methods("PATCH")

	// Version history
	router.HandleFunc("/api/v1/static-policies/{id}/versions", handler.HandleGetVersionHistory).Methods("GET")

	// Override endpoints (Enterprise only)
	router.HandleFunc("/api/v1/static-policies/{id}/override", handler.HandleCreateOverride).Methods("POST")
	router.HandleFunc("/api/v1/static-policies/{id}/override", handler.HandleDeleteOverride).Methods("DELETE")

	log.Println("✅ Static Policy API routes registered (11 endpoints)")
}

// HandleListStaticPolicies handles GET /api/v1/static-policies
// Query parameters:
//   - page: Page number (default: 1)
//   - page_size: Items per page (default: 20, max: 100)
//   - category: Filter by category (security-sqli, pii-global, etc.)
//   - tier: Filter by tier (system, organization, tenant)
//   - severity: Filter by severity (low, medium, high, critical)
//   - enabled: Filter by enabled status (true/false)
//   - search: Search in name and description
//
// Headers:
//   - X-Tenant-ID: Tenant ID for scoping (required in SaaS mode)
//   - X-Organization-ID: Organization ID for org-level filtering
func (h *StaticPolicyAPIHandler) HandleListStaticPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := r.Header.Get("X-Tenant-ID")

	// Parse pagination parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	// Build filter params
	params := &ListStaticPoliciesParams{
		Page:     page,
		PageSize: pageSize,
		Search:   r.URL.Query().Get("search"),
	}

	// Parse tier filter
	if tierStr := r.URL.Query().Get("tier"); tierStr != "" {
		tier := PolicyTier(tierStr)
		if IsValidTier(tier) {
			params.Tier = &tier
		}
	}

	// Parse category filter
	if categoryStr := r.URL.Query().Get("category"); categoryStr != "" {
		category := PolicyCategory(categoryStr)
		params.Category = &category
	}

	// Parse enabled filter
	if enabledStr := r.URL.Query().Get("enabled"); enabledStr != "" {
		enabled := enabledStr == "true"
		params.Enabled = &enabled
	}

	// Execute list query using repository
	response, err := h.policyRepo.List(ctx, tenantID, params)
	if err != nil {
		log.Printf("[StaticPolicyAPI] Error listing policies: %v", err)
		writeJSONError(w, "Failed to list policies", http.StatusInternalServerError)
		return
	}

	log.Printf("[StaticPolicyAPI] Returning %d policies (page %d/%d, tenant: %s)",
		len(response.Policies), response.Pagination.Page, response.Pagination.TotalPages, tenantID)

	writeJSONResponse(w, response, http.StatusOK)
}

// HandleCreateStaticPolicy handles POST /api/v1/static-policies
// Request body: CreateStaticPolicyRequest
// Headers:
//   - X-Tenant-ID: Tenant ID (required)
//   - X-Organization-ID: Organization ID (required for org-tier policies)
//   - X-User-ID: User ID for audit trail
func (h *StaticPolicyAPIHandler) HandleCreateStaticPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := r.Header.Get("X-Tenant-ID")
	orgID := r.Header.Get("X-Organization-ID")
	userID := r.Header.Get("X-User-ID")

	if tenantID == "" {
		writeJSONError(w, "X-Tenant-ID header required", http.StatusBadRequest)
		return
	}

	// Parse request body
	var req CreateStaticPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Name == "" {
		writeJSONError(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.Pattern == "" {
		writeJSONError(w, "pattern is required", http.StatusBadRequest)
		return
	}
	if req.Category == "" {
		writeJSONError(w, "category is required", http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		writeJSONError(w, "action is required", http.StatusBadRequest)
		return
	}

	// Build policy from request
	// Default tier to "tenant" if not provided
	tier := req.Tier
	if tier == "" {
		tier = TierTenant
	}

	policy := &StaticPolicy{
		Name:        req.Name,
		Description: req.Description,
		Category:    req.Category,
		Tier:        tier,
		Pattern:     req.Pattern,
		Action:      req.Action,
		Severity:    req.Severity,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
		Tags:        req.Tags,
		TenantID:    tenantID,
		OrgID:       orgID,
	}

	// Set organization ID for org-tier policies
	if tier == TierOrganization && orgID != "" {
		policy.OrganizationID = &orgID
	}

	// Create policy using repository
	if err := h.policyRepo.Create(ctx, policy, userID); err != nil {
		log.Printf("[StaticPolicyAPI] Error creating policy: %v", err)

		// Return appropriate status code based on error type
		switch {
		case errors.Is(err, ErrSystemTierCreation):
			writeJSONError(w, "Cannot create system-tier policies via API", http.StatusForbidden)
		case errors.Is(err, ErrOrgTierRequiresEnterprise):
			writeJSONError(w, "Organization tier requires Enterprise license", http.StatusForbidden)
		case errors.Is(err, ErrTenantPolicyLimitReached):
			writeJSONError(w, "Tenant policy limit reached (30 max for Community)", http.StatusForbidden)
		case errors.Is(err, ErrInvalidPattern):
			writeJSONError(w, "Invalid regex pattern: "+err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrInvalidCategory):
			writeJSONError(w, "Invalid policy category", http.StatusBadRequest)
		case errors.Is(err, ErrInvalidTier):
			writeJSONError(w, "Invalid policy tier", http.StatusBadRequest)
		default:
			writeJSONError(w, "Failed to create policy", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[StaticPolicyAPI] Created policy %s (tier: %s, tenant: %s)", policy.PolicyID, policy.Tier, tenantID)

	writeJSONResponse(w, policy, http.StatusCreated)
}

// HandleGetStaticPolicy handles GET /api/v1/static-policies/{id}
func (h *StaticPolicyAPIHandler) HandleGetStaticPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["id"]

	policy, err := h.policyRepo.GetByID(ctx, policyID)
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			writeJSONError(w, "Policy not found", http.StatusNotFound)
			return
		}
		log.Printf("[StaticPolicyAPI] Error getting policy %s: %v", policyID, err)
		writeJSONError(w, "Failed to get policy", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, policy, http.StatusOK)
}

// HandleUpdateStaticPolicy handles PUT /api/v1/static-policies/{id}
// Request body: UpdateStaticPolicyRequest
func (h *StaticPolicyAPIHandler) HandleUpdateStaticPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["id"]
	userID := r.Header.Get("X-User-ID")

	// Parse request body
	var req UpdateStaticPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Update policy using repository
	policy, err := h.policyRepo.Update(ctx, policyID, &req, userID)
	if err != nil {
		log.Printf("[StaticPolicyAPI] Error updating policy %s: %v", policyID, err)

		switch {
		case errors.Is(err, ErrPolicyNotFound):
			writeJSONError(w, "Policy not found", http.StatusNotFound)
		case errors.Is(err, ErrSystemPolicyModification):
			writeJSONError(w, "System policies cannot be modified", http.StatusForbidden)
		case errors.Is(err, ErrInvalidPattern):
			writeJSONError(w, "Invalid regex pattern: "+err.Error(), http.StatusBadRequest)
		default:
			writeJSONError(w, "Failed to update policy", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[StaticPolicyAPI] Updated policy %s (version: %d)", policyID, policy.Version)

	writeJSONResponse(w, policy, http.StatusOK)
}

// HandleDeleteStaticPolicy handles DELETE /api/v1/static-policies/{id}
// Performs soft delete (sets deleted_at timestamp)
func (h *StaticPolicyAPIHandler) HandleDeleteStaticPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["id"]
	userID := r.Header.Get("X-User-ID")

	if err := h.policyRepo.Delete(ctx, policyID, userID); err != nil {
		log.Printf("[StaticPolicyAPI] Error deleting policy %s: %v", policyID, err)

		switch {
		case errors.Is(err, ErrPolicyNotFound):
			writeJSONError(w, "Policy not found", http.StatusNotFound)
		case errors.Is(err, ErrSystemPolicyDeletion):
			writeJSONError(w, "System policies cannot be deleted", http.StatusForbidden)
		default:
			writeJSONError(w, "Failed to delete policy", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[StaticPolicyAPI] Deleted policy %s (soft delete)", policyID)

	w.WriteHeader(http.StatusNoContent)
}

// HandleTogglePolicy handles PATCH /api/v1/static-policies/{id}
// Toggles the enabled status of a policy
// Request body: {"enabled": true/false}
func (h *StaticPolicyAPIHandler) HandleTogglePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["id"]
	userID := r.Header.Get("X-User-ID")

	// Parse request body
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.policyRepo.ToggleEnabled(ctx, policyID, req.Enabled, userID); err != nil {
		log.Printf("[StaticPolicyAPI] Error toggling policy %s: %v", policyID, err)

		switch {
		case errors.Is(err, ErrPolicyNotFound):
			writeJSONError(w, "Policy not found", http.StatusNotFound)
		case errors.Is(err, ErrSystemPolicyModification):
			writeJSONError(w, "System policies cannot be disabled via API", http.StatusForbidden)
		default:
			writeJSONError(w, "Failed to toggle policy", http.StatusInternalServerError)
		}
		return
	}

	// Fetch the updated policy to return
	policy, err := h.policyRepo.GetByID(ctx, policyID)
	if err != nil {
		log.Printf("[StaticPolicyAPI] Error fetching toggled policy %s: %v", policyID, err)
		writeJSONError(w, "Failed to fetch updated policy", http.StatusInternalServerError)
		return
	}

	log.Printf("[StaticPolicyAPI] Toggled policy %s enabled=%v", policyID, req.Enabled)

	writeJSONResponse(w, policy, http.StatusOK)
}

// HandleGetEffectivePolicies handles GET /api/v1/static-policies/effective
// Returns all effective policies for a tenant with overrides applied.
// This is used by the Customer Portal for the unified policy view.
func (h *StaticPolicyAPIHandler) HandleGetEffectivePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := r.Header.Get("X-Tenant-ID")
	orgIDHeader := r.Header.Get("X-Organization-ID")

	if tenantID == "" {
		writeJSONError(w, "X-Tenant-ID header required", http.StatusBadRequest)
		return
	}

	// Convert orgID to pointer (nil if empty)
	var orgID *string
	if orgIDHeader != "" {
		orgID = &orgIDHeader
	}

	// Get effective policies (with overrides applied)
	policies, err := h.policyRepo.GetEffective(ctx, tenantID, orgID)
	if err != nil {
		log.Printf("[StaticPolicyAPI] Error getting effective policies: %v", err)
		writeJSONError(w, "Failed to get effective policies", http.StatusInternalServerError)
		return
	}

	response := EffectivePolicies{
		Static:         policies,
		TenantID:       tenantID,
		OrganizationID: orgIDHeader,
		ComputedAt:     time.Now().UTC(),
	}

	log.Printf("[StaticPolicyAPI] Returning %d effective policies for tenant %s", len(policies), tenantID)

	writeJSONResponse(w, response, http.StatusOK)
}

// TestPatternAPIRequest is the request body for testing a pattern via API.
type TestPatternAPIRequest struct {
	Pattern string   `json:"pattern"`
	Inputs  []string `json:"inputs"`
	// Single input for backward compatibility
	Input string `json:"input,omitempty"`
}

// HandleTestPattern handles POST /api/v1/static-policies/test
// Tests a regex pattern against input strings
// Request body: {"pattern": "...", "inputs": ["input1", "input2"]}
// or: {"pattern": "...", "input": "single input"} for backward compatibility
func (h *StaticPolicyAPIHandler) HandleTestPattern(w http.ResponseWriter, r *http.Request) {
	var req TestPatternAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Pattern == "" {
		writeJSONError(w, "pattern is required", http.StatusBadRequest)
		return
	}

	// Support both "inputs" array and single "input" for backward compatibility
	inputs := req.Inputs
	if len(inputs) == 0 && req.Input != "" {
		inputs = []string{req.Input}
	}

	// Create a context with timeout for pattern testing
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Validate and test the pattern
	result := TestPattern(ctx, req.Pattern, inputs)

	writeJSONResponse(w, result, http.StatusOK)
}

// HandleGetVersionHistory handles GET /api/v1/static-policies/{id}/versions
// Returns version history for a policy.
// Community edition: limited to 5 versions
// Enterprise edition: unlimited
func (h *StaticPolicyAPIHandler) HandleGetVersionHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	versions, err := h.policyRepo.GetVersions(ctx, policyID, tenantID)
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			writeJSONError(w, "Policy not found", http.StatusNotFound)
			return
		}
		log.Printf("[StaticPolicyAPI] Error getting versions for policy %s: %v", policyID, err)
		writeJSONError(w, "Failed to get version history", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"policy_id": policyID,
		"versions":  versions,
		"count":     len(versions),
	}

	writeJSONResponse(w, response, http.StatusOK)
}

// HandleCreateOverride handles POST /api/v1/static-policies/{id}/override
// Creates an override for a system policy (Enterprise only)
// Request body: CreateOverrideRequest
func (h *StaticPolicyAPIHandler) HandleCreateOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")
	orgID := r.Header.Get("X-Organization-ID")
	userID := r.Header.Get("X-User-ID")

	if tenantID == "" {
		writeJSONError(w, "X-Tenant-ID header required", http.StatusBadRequest)
		return
	}

	// Parse request body
	var req CreateOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Build override
	override := &PolicyOverride{
		PolicyID:        policyID,
		PolicyType:      TypeStatic,
		ActionOverride:  req.ActionOverride,
		EnabledOverride: req.EnabledOverride,
		OverrideReason:  req.OverrideReason,
		ExpiresAt:       req.ExpiresAt,
	}

	// Set scope based on headers
	if orgID != "" {
		override.OrganizationID = &orgID
	}
	if tenantID != "" {
		override.TenantID = &tenantID
	}

	// Create override using repository
	if err := h.overrideRepo.Create(ctx, override, userID); err != nil {
		log.Printf("[StaticPolicyAPI] Error creating override for policy %s: %v", policyID, err)

		switch {
		case errors.Is(err, ErrOverrideReasonRequired):
			writeJSONError(w, "override_reason is required", http.StatusBadRequest)
		case errors.Is(err, ErrOverrideRequiresEnterprise):
			writeJSONError(w, "Policy overrides require Enterprise license", http.StatusForbidden)
		case errors.Is(err, ErrOverrideAlreadyExists):
			writeJSONError(w, "Override already exists for this policy", http.StatusConflict)
		default:
			writeJSONError(w, "Failed to create override: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[StaticPolicyAPI] Created override for policy %s (tenant: %s)", policyID, tenantID)

	writeJSONResponse(w, override, http.StatusCreated)
}

// HandleDeleteOverride handles DELETE /api/v1/static-policies/{id}/override
// Deletes an override for a policy
func (h *StaticPolicyAPIHandler) HandleDeleteOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["id"]
	tenantIDHeader := r.Header.Get("X-Tenant-ID")
	orgIDHeader := r.Header.Get("X-Organization-ID")
	userID := r.Header.Get("X-User-ID")

	if tenantIDHeader == "" {
		writeJSONError(w, "X-Tenant-ID header required", http.StatusBadRequest)
		return
	}

	// Convert to pointers for repository call
	var tenantID, orgID *string
	if tenantIDHeader != "" {
		tenantID = &tenantIDHeader
	}
	if orgIDHeader != "" {
		orgID = &orgIDHeader
	}

	// Delete override using repository
	if err := h.overrideRepo.DeleteByPolicyID(ctx, policyID, tenantID, orgID, userID); err != nil {
		if errors.Is(err, ErrOverrideNotFound) {
			writeJSONError(w, "Override not found", http.StatusNotFound)
			return
		}
		log.Printf("[StaticPolicyAPI] Error deleting override for policy %s: %v", policyID, err)
		writeJSONError(w, "Failed to delete override", http.StatusInternalServerError)
		return
	}

	log.Printf("[StaticPolicyAPI] Deleted override for policy %s (tenant: %s)", policyID, tenantIDHeader)

	w.WriteHeader(http.StatusNoContent)
}

// writeJSONResponse writes a JSON response with the given status code
func writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[StaticPolicyAPI] Error encoding response: %v", err)
	}
}

// writeJSONError writes a JSON error response
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    statusCode,
			"message": message,
		},
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[StaticPolicyAPI] Error encoding error response: %v", err)
	}
}
