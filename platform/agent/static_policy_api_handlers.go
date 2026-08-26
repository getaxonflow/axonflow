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
// API Endpoints, served under BOTH /api/v1/system-policies (#1431, current)
// and /api/v1/static-policies (deprecated, still served):
//
//   - GET    {prefix}                - List policies with filtering
//   - POST   {prefix}                - Create a new policy
//   - GET    {prefix}/{id}           - Get policy by ID
//   - PUT    {prefix}/{id}           - Update policy
//   - DELETE {prefix}/{id}           - Soft delete policy
//   - PATCH  {prefix}/{id}           - Toggle enabled status
//   - GET    {prefix}/effective      - Get effective policies with overrides
//   - POST   {prefix}/test           - Test a pattern against input
//   - GET    {prefix}/overrides      - List tenant-wide overrides
//   - GET    {prefix}/{id}/versions  - Get version history
//   - GET    {prefix}/{id}/override  - Read override (Enterprise)
//   - POST   {prefix}/{id}/override  - Create override (Enterprise)
//   - DELETE {prefix}/{id}/override  - Delete override (Enterprise)
//
// The two prefixes are the SAME routes against the SAME handler values; see
// systemPolicyRoutes and package axonflow/platform/shared/policypath.
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

	"axonflow/platform/shared/policypath"
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

// systemPolicyRoute is one (suffix, methods, handler) triple in the system
// policy API. The table exists so that the legacy /api/v1/static-policies
// prefix and its #1431 successor /api/v1/system-policies are registered from
// ONE list against ONE handler value.
//
// Writing the two prefixes out as two blocks of HandleFunc lines would be a
// fork wearing an alias's clothes: the next person to add a route would add it
// to whichever block they were looking at, and the alias would quietly serve a
// subset. Here, adding a row adds it to both, and there is no arrangement of
// this code in which the two prefixes carry different routes.
type systemPolicyRoute struct {
	suffix  string
	methods []string
	handler http.HandlerFunc
}

// systemPolicyRoutes returns the route table. Order matters and is preserved:
// gorilla/mux matches in registration order, so the literal-suffix routes
// ("/effective", "/test", "/overrides") MUST precede "/{id}" or "effective"
// is swallowed as an id.
func systemPolicyRoutes(h *StaticPolicyAPIHandler) []systemPolicyRoute {
	return []systemPolicyRoute{
		// List and effective endpoints (must come before {id} routes)
		{"", []string{"GET"}, h.HandleListStaticPolicies},
		{"", []string{"POST"}, h.HandleCreateStaticPolicy},
		{"/effective", []string{"GET"}, h.HandleGetEffectivePolicies},
		{"/test", []string{"POST"}, h.HandleTestPattern},
		{"/overrides", []string{"GET"}, h.HandleListOverrides},

		// Single policy operations (must come after literal path routes)
		{"/{id}", []string{"GET"}, h.HandleGetStaticPolicy},
		{"/{id}", []string{"PUT"}, h.HandleUpdateStaticPolicy},
		{"/{id}", []string{"DELETE"}, h.HandleDeleteStaticPolicy},
		{"/{id}", []string{"PATCH"}, h.HandleTogglePolicy},

		// Version history
		{"/{id}/versions", []string{"GET"}, h.HandleGetVersionHistory},

		// Override endpoints (Enterprise only)
		{"/{id}/override", []string{"GET"}, h.HandleGetOverrideByPolicy},
		{"/{id}/override", []string{"POST"}, h.HandleCreateOverride},
		{"/{id}/override", []string{"DELETE"}, h.HandleDeleteOverride},
	}
}

// RegisterStaticPolicyHandlers registers the system policy API routes under
// both the legacy /api/v1/static-policies prefix and the #1431 successor
// /api/v1/system-policies.
//
// EDITION (HARD RULE 11): this is a rename, not a capability. Both prefixes
// are registered by this one function, from one table, at one call site
// (run.go), so whatever edition gating reaches the legacy prefix reaches the
// successor by construction. There is no second condition to keep in sync -
// including the per-route Enterprise gating on the /override endpoints, which
// lives inside the handlers and is therefore shared by both prefixes.
func RegisterStaticPolicyHandlers(router *mux.Router, db *sql.DB) {
	if db == nil {
		log.Println("⚠️ Database not available - Static Policy API disabled")
		return
	}

	handler := NewStaticPolicyAPIHandler(db)
	routes := systemPolicyRoutes(handler)

	// All system policy routes are protected by apiAuthMiddleware.
	// Tenant identity is derived from OAuth2 client credentials (Basic auth),
	// not from X-Tenant-ID header. Handlers read tenant via TenantIDFromContext().
	//
	// The legacy prefix additionally carries the deprecation stamp, mounted
	// BEFORE apiAuthMiddleware so the signal rides an unauthenticated 401 as
	// well as a 200: "this path is deprecated" is a property of the path, not
	// of the caller's credentials, and a client discovering the API with a bad
	// token should still learn it.
	//
	// The limit of that, stated because the sentence above overclaims if left
	// alone: gorilla/mux runs subrouter middleware only on a MATCHED route. A
	// request under this prefix that matches no route, or matches a path on a
	// method it is not registered for, gets a 404 with NO deprecation header.
	// Measured, not assumed - DELETE /api/v1/static-policies and
	// GET /api/v1/static-policies/abc/nope both answer 404 bare, while
	// GET /api/v1/static-policies answers 401 WITH the header. Signalling on a
	// 404 would mean asserting a path exists in order to deprecate it, so this
	// is left as it is rather than worked around.
	legacy := router.PathPrefix(policypath.LegacySystemPolicies).Subrouter()
	legacy.Use(policypath.DeprecateLegacy)
	legacy.Use(apiAuthMiddleware)

	successor := router.PathPrefix(policypath.SystemPolicies).Subrouter()
	successor.Use(apiAuthMiddleware)

	for _, sub := range []*mux.Router{legacy, successor} {
		for _, rt := range routes {
			sub.HandleFunc(rt.suffix, rt.handler).Methods(rt.methods...)
		}
	}

	log.Printf("✅ System Policy API routes registered (%d endpoints x 2 prefixes, auth-protected): %s (deprecated) and %s",
		len(routes), policypath.LegacySystemPolicies, policypath.SystemPolicies)

	// Canonical policy-overrides alias — customer-portal (and any external
	// client looking for a tenant-wide override list) expects this path.
	// Previously only /api/v1/static-policies/overrides was reachable, and
	// the portal was hitting this path and getting 404s.
	overridesAlias := router.PathPrefix("/api/v1/policy-overrides").Subrouter()
	overridesAlias.Use(apiAuthMiddleware)
	overridesAlias.HandleFunc("", handler.HandleListOverrides).Methods("GET")
	log.Println("✅ Canonical /api/v1/policy-overrides alias registered (GET, auth-protected)")
}

// HandleListStaticPolicies handles GET /api/v1/static-policies
// Query parameters:
//   - page: Page number (default: 1)
//   - limit: Items per page (default: 20, max: 100)
//   - page_size: Deprecated - use limit instead
//   - category: Filter by category (security-sqli, pii-global, etc.)
//   - tier: Filter by tier (system, organization, tenant)
//   - severity: Filter by severity (low, medium, high, critical)
//   - enabled: Filter by enabled status (true/false)
//   - search: Search in name and description
//
// Headers:
//   Auth: OAuth2 Client Credentials (Basic auth) — tenant derived from authenticated client
func (h *StaticPolicyAPIHandler) HandleListStaticPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := TenantIDFromContext(ctx)

	// Parse pagination parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	// Accept both limit (preferred) and page_size (deprecated) for backward compatibility
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if pageSize < 1 {
		pageSize, _ = strconv.Atoi(r.URL.Query().Get("page_size"))
	}
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
//   Auth: OAuth2 Client Credentials (Basic auth) — tenant and org derived from authenticated client
//   - X-User-ID: User ID for audit trail
func (h *StaticPolicyAPIHandler) HandleCreateStaticPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := TenantIDFromContext(ctx)
	orgID := OrgIDFromContext(ctx)
	userID := r.Header.Get("X-User-ID")

	if tenantID == "" {
		writeJSONError(w, "Authentication required — tenant could not be determined", http.StatusUnauthorized)
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

	// #3334: the "prefer request body organization_id over header" block that
	// used to live here is gone with the column it wrote. It let a request
	// BODY name the organisation a policy belongs to, falling back to the
	// authenticated header only when the body said nothing - which is the
	// wrong precedence for a tenancy key regardless of the column being
	// retired. policy.OrgID above is the AUTHENTICATED caller's org and is
	// the only organisation this policy can be created under, for every tier.

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
	tenantID := TenantIDFromContext(ctx)
	orgIDHeader := OrgIDFromContext(ctx)

	if tenantID == "" {
		writeJSONError(w, "Authentication required — tenant could not be determined", http.StatusUnauthorized)
		return
	}

	// Convert orgID to pointer (nil if empty)
	var orgID *string
	if orgIDHeader != "" {
		orgID = &orgIDHeader
	}

	// Get effective policies (with overrides applied). Segment-scoped policies
	// are intentionally excluded here (nil segmentIDs): this endpoint is the
	// portal's admin/unified-policy VIEW, which has no verified per-viewer
	// segment membership to resolve against (that's a P6, #2989, concern —
	// the portal write/view path for segment-scoped authoring). It shows the
	// org-wide tier-effective policy set exactly as before P3.
	policies, err := h.policyRepo.GetEffective(ctx, tenantID, orgID, nil)
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
	tenantID := TenantIDFromContext(ctx)

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
	tenantID := TenantIDFromContext(ctx)
	orgID := OrgIDFromContext(ctx)
	userID := r.Header.Get("X-User-ID")

	if tenantID == "" {
		writeJSONError(w, "Authentication required — tenant could not be determined", http.StatusUnauthorized)
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
		// v9 Phase 8 #2384 PR-C1: OrgID is the multi-tenant RLS scope key
		// (post mig 110). Sourced from the X-Org-ID header set by the agent
		// auth middleware; falls back to tenant for the OrgID==TenantID
		// invariant of mig 100 / community-saas mode.
		OrgID: func() string {
			if orgID != "" {
				return orgID
			}
			return tenantID
		}(),
	}

	// Set scope based on headers.
	//
	// AxonFlow org ids are FREE-FORM STRINGS sourced from the signed license
	// (e.g. "acme-eval") — they are NOT UUIDs. The multi-tenant scope key
	// for policy_overrides is the varchar `org_id` column (added by v9 mig 110,
	// carried here by override.OrgID) plus `tenant_id`. The legacy
	// `organization_id` column is a `uuid` type; binding a non-uuid org id to it
	// makes the INSERT fail with `invalid input syntax for type uuid: "<org>"`,
	// which was a hard 500 on the portal "Create Override" flow for every
	// deployment whose org id is not UUID-shaped. Do NOT write the string org id
	// into the uuid column — org scope lives in org_id (set above via OrgID);
	// tenant_id below satisfies the valid_override_scope CHECK and is the match
	// key for both the existence check and the GetEffective apply-JOIN.
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
	tenantIDHeader := TenantIDFromContext(ctx)
	orgIDHeader := OrgIDFromContext(ctx)
	userID := r.Header.Get("X-User-ID")

	if tenantIDHeader == "" {
		writeJSONError(w, "Authentication required — tenant could not be determined", http.StatusUnauthorized)
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

	// Delete override using repository.
	// v9 Phase 8 #2384 PR-C1: rlsOrgID is the auth'd request's OrgID (mig 110
	// requires app.current_org_id pinned for policy_overrides DELETE).
	// orgIDHeader (set by the agent auth middleware) is the V9 scope key;
	// fall back to tenantIDHeader for community-saas / OrgID==TenantID
	// invariant (mig 100). This mirrors HandleCreateOverride's fallback so
	// the Create/Delete pair behaves symmetrically — without the fallback,
	// internal-service callers (no X-Org-ID) get 500s on Delete while
	// Create succeeds.
	rlsOrgID := orgIDHeader
	if rlsOrgID == "" {
		rlsOrgID = tenantIDHeader
	}
	if err := h.overrideRepo.DeleteByPolicyID(ctx, rlsOrgID, policyID, tenantID, orgID, userID); err != nil {
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

// HandleGetOverrideByPolicy handles GET /api/v1/static-policies/{id}/override.
// Returns the active override for a single policy (404 if none). Previously only
// POST/DELETE were registered on this path, so the portal's "get override" proxy
// received a 405. {id} may be the policy UUID or the human-readable slug.
func (h *StaticPolicyAPIHandler) HandleGetOverrideByPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policyID := mux.Vars(r)["id"]
	tenantIDHeader := TenantIDFromContext(ctx)
	orgIDHeader := OrgIDFromContext(ctx)

	if tenantIDHeader == "" {
		writeJSONError(w, "Authentication required — tenant could not be determined", http.StatusUnauthorized)
		return
	}

	// Resolve slug → canonical UUID so a caller passing either identifier gets a
	// consistent result (overrides are keyed by the static_policies UUID).
	if resolved, err := h.policyRepo.GetByID(ctx, policyID); err == nil && resolved != nil && resolved.ID != "" {
		policyID = resolved.ID
	}

	var tenantID, orgID *string
	if tenantIDHeader != "" {
		tenantID = &tenantIDHeader
	}
	if orgIDHeader != "" {
		orgID = &orgIDHeader
	}

	override, err := h.overrideRepo.GetOverrideForPolicy(ctx, policyID, tenantID, orgID)
	if err != nil {
		if errors.Is(err, ErrOverrideNotFound) {
			writeJSONError(w, "Override not found", http.StatusNotFound)
			return
		}
		log.Printf("[StaticPolicyAPI] Error getting override for policy %s: %v", policyID, err)
		writeJSONError(w, "Failed to get override", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, override, http.StatusOK)
}

// HandleListOverrides handles GET /api/v1/static-policies/overrides
// Lists all policy overrides for a tenant
// Headers:
//   Auth: OAuth2 Client Credentials (Basic auth) — tenant derived from authenticated client
func (h *StaticPolicyAPIHandler) HandleListOverrides(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDHeader := TenantIDFromContext(ctx)
	orgIDHeader := OrgIDFromContext(ctx)

	if tenantIDHeader == "" {
		writeJSONError(w, "Authentication required — tenant could not be determined", http.StatusUnauthorized)
		return
	}

	// Convert orgID to pointer (nil if empty)
	var orgID *string
	if orgIDHeader != "" {
		orgID = &orgIDHeader
	}

	// Parse include_expired query param
	includeExpired := r.URL.Query().Get("include_expired") == "true"

	// List overrides using repository
	overrides, err := h.overrideRepo.ListOverridesForTenant(ctx, tenantIDHeader, orgID, includeExpired)
	if err != nil {
		log.Printf("[StaticPolicyAPI] Error listing overrides: %v", err)
		writeJSONError(w, "Failed to list overrides", http.StatusInternalServerError)
		return
	}

	log.Printf("[StaticPolicyAPI] Returning %d overrides for tenant %s", len(overrides), tenantIDHeader)

	response := map[string]interface{}{
		"overrides": overrides,
		"count":     len(overrides),
	}

	writeJSONResponse(w, response, http.StatusOK)
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
