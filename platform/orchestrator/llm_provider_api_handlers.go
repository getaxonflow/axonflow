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

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/llm"
	_ "axonflow/platform/orchestrator/llm/openai"
	_ "axonflow/platform/orchestrator/llm/providers"
	logutil "axonflow/platform/shared/logger"
)

// Note: maxRequestBodySize and allowedOrigins are defined in policy_api_handlers.go
// to avoid duplicate declarations within the same package.

// LLMProviderAPIHandler handles HTTP requests for LLM provider management.
// This is the gorilla/mux compatible version that integrates with the orchestrator router.
type LLMProviderAPIHandler struct {
	registry *llm.Registry
	router   *llm.Router
	logger   *log.Logger
}

// NewLLMProviderAPIHandler creates a new LLM provider API handler.
// Deprecated: Use NewLLMProviderAPIHandlerWithRouter for new llm.Router integration.
func NewLLMProviderAPIHandler(registry *llm.Registry, router *llm.Router) *LLMProviderAPIHandler {
	return &LLMProviderAPIHandler{
		registry: registry,
		router:   router,
		logger:   log.Default(),
	}
}

// NewLLMProviderAPIHandlerWithRouter creates a new LLM provider API handler using the new Router.
// This constructor is used when the bootstrap system has been initialized.
// Returns nil if router is nil or router's registry is nil.
func NewLLMProviderAPIHandlerWithRouter(router *llm.Router, logger *log.Logger) *LLMProviderAPIHandler {
	if router == nil {
		return nil
	}
	registry := router.Registry()
	if registry == nil {
		return nil
	}
	if logger == nil {
		logger = log.Default()
	}
	return &LLMProviderAPIHandler{
		registry: registry,
		router:   router,
		logger:   logger,
	}
}

// RegisterRoutesWithMux registers LLM provider API routes with a gorilla/mux router.
// This is the primary method for wiring the LLM provider API into the orchestrator.
//
// IMPORTANT: Route order matters in gorilla/mux! More specific routes (like /routing, /status)
// MUST be registered BEFORE parameterized routes (like /{name}) to avoid the parameter
// capturing literal path segments.
func (h *LLMProviderAPIHandler) RegisterRoutesWithMux(r *mux.Router) {
	// Factory info (available provider types) - no path params
	r.HandleFunc("/api/v1/llm-provider-types", h.handleListProviderTypes).Methods("GET", "OPTIONS")

	// Provider collection endpoints - no path params
	r.HandleFunc("/api/v1/llm-providers", h.handleListOrCreate).Methods("GET", "POST", "OPTIONS")

	// IMPORTANT: These specific paths MUST come BEFORE /{name} to prevent
	// the {name} parameter from capturing "routing" or "status" as provider names
	r.HandleFunc("/api/v1/llm-providers/routing", h.handleRoutingMux).Methods("GET", "PUT", "OPTIONS")
	r.HandleFunc("/api/v1/llm-providers/status", h.handleAllProvidersStatusMux).Methods("GET", "OPTIONS")

	// Parameterized routes - MUST come AFTER specific literal paths
	r.HandleFunc("/api/v1/llm-providers/{name}", h.handleGetUpdateDelete).Methods("GET", "PUT", "DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/llm-providers/{name}/health", h.handleProviderHealthMux).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/llm-providers/{name}/test", h.handleTestProvider).Methods("POST", "OPTIONS")
}

// callerTenantID resolves the tenancy of an LLM-provider API request.
//
// X-Tenant-ID / X-Org-ID are set authoritatively by the agent's auth chain
// (apiAuthMiddleware does `r.Header.Set`, overwriting anything the client
// sent) before the request is proxied to the orchestrator — the same source
// the create/update/delete handlers have used since #2384. The empty string
// means "no tenancy asserted"; every caller of this helper refuses the
// request rather than falling back to a deployment-wide view (#3067).
func callerTenantID(r *http.Request) string {
	// The GlobalTenant sentinel is never a legitimate caller identity: it is
	// the registry's internal scope for the deployment's own providers, so a
	// caller asserting it would own the entire deployment pool (R3).
	pick := func(v string) string {
		if v == llm.GlobalTenant {
			return ""
		}
		return v
	}
	if tenantID := pick(r.Header.Get("X-Tenant-ID")); tenantID != "" {
		return tenantID
	}
	return pick(r.Header.Get("X-Org-ID"))
}

// requireTenantID resolves the caller's tenancy or writes the 400 and returns
// false. Read handlers use it for the same reason the write handlers do: an
// unscoped read of this registry is a cross-tenant disclosure (#3067 S-3).
func (h *LLMProviderAPIHandler) requireTenantID(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenantID := callerTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "X-Tenant-ID or X-Org-ID header is required")
		return "", false
	}
	return tenantID, true
}

// handleListOrCreate handles GET (list) and POST (create) for /api/v1/llm-providers.
func (h *LLMProviderAPIHandler) handleListOrCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleListProvidersMux(w, r)
	case http.MethodPost:
		h.handleCreateProviderMux(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

// handleGetUpdateDelete handles GET/PUT/DELETE for /api/v1/llm-providers/{name}.
// Note: Routes for /routing and /status are registered separately with higher priority,
// so {name} will never capture those literal values.
func (h *LLMProviderAPIHandler) handleGetUpdateDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	vars := mux.Vars(r)
	providerName := vars["name"]

	switch r.Method {
	case http.MethodGet:
		h.handleGetProviderMux(w, r, providerName)
	case http.MethodPut:
		h.handleUpdateProviderMux(w, r, providerName)
	case http.MethodDelete:
		h.handleDeleteProviderMux(w, r, providerName)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

// handleListProvidersMux handles GET /api/v1/llm-providers.
func (h *LLMProviderAPIHandler) handleListProvidersMux(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	params := LLMProviderListParams{
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

	if providerType := r.URL.Query().Get("type"); providerType != "" {
		params.Type = llm.ProviderType(providerType)
	}

	if enabledStr := r.URL.Query().Get("enabled"); enabledStr != "" {
		enabled := enabledStr == "true"
		params.Enabled = &enabled
	}

	// Provider names visible to this tenant (its own + the deployment's).
	// #3067 (S-3): this used to list EVERY tenant's providers, disclosing
	// name/type/endpoint/model/region/priority/weight/rate_limit/settings/
	// has_api_key/health for all of them.
	names := h.registry.List(tenantID)

	// Apply filters and build response
	providers := make([]LLMProviderResource, 0, len(names))
	for _, name := range names {
		provider, err := h.registry.Get(r.Context(), tenantID, name)
		if err != nil {
			continue
		}

		// Type filter
		if params.Type != "" && provider.Type() != params.Type {
			continue
		}

		// Get config from registry
		config, err := h.registry.GetConfig(tenantID, name)
		if err != nil || config == nil {
			continue
		}

		// Enabled filter
		if params.Enabled != nil && config.Enabled != *params.Enabled {
			continue
		}

		healthResult := h.registry.GetHealthResult(tenantID, name)
		providers = append(providers, toProviderResource(config, healthResult))
	}

	// Apply pagination
	total := len(providers)
	start := (params.Page - 1) * params.PageSize
	end := start + params.PageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginatedProviders := providers[start:end]

	response := LLMProviderListResponse{
		Providers: paginatedProviders,
		Pagination: PaginationMeta{
			Page:       params.Page,
			PageSize:   params.PageSize,
			TotalItems: total,
			TotalPages: (total + params.PageSize - 1) / params.PageSize,
		},
	}

	h.writeJSON(w, http.StatusOK, response)
}

// handleCreateProviderMux handles POST /api/v1/llm-providers.
func (h *LLMProviderAPIHandler) handleCreateProviderMux(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req CreateLLMProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body")
		return
	}

	// Validate required fields
	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}
	if req.Type == "" {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "type is required")
		return
	}

	// Validate provider type using factory
	providerType := llm.ProviderType(req.Type)
	if !llm.HasFactory(providerType) {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "unsupported provider type: "+req.Type)
		return
	}

	// v9 Phase 8 PR-C2 (#2384): the LLM-provider storage layer wraps INSERTs
	// in WithOrgScope using config.TenantID. The handler is the only place
	// with the per-request identity in scope — propagate it.
	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	// Check if THIS tenant already has a provider by that name. #3067: the
	// deployment-wide check was an existence oracle — a 409 told the caller
	// that some other tenant had registered that provider name.
	if h.registry.OwnsProvider(tenantID, req.Name) {
		h.writeError(w, http.StatusConflict, "CONFLICT", "provider with this name already exists")
		return
	}

	// Build config
	config := &llm.ProviderConfig{
		Name:            req.Name,
		Type:            providerType,
		APIKey:          req.APIKey,
		APIKeySecretARN: req.APIKeySecretARN,
		Endpoint:        req.Endpoint,
		Model:           req.Model,
		Region:          req.Region,
		Enabled:         req.Enabled,
		Priority:        req.Priority,
		Weight:          req.Weight,
		RateLimit:       req.RateLimit,
		TimeoutSeconds:  req.TimeoutSeconds,
		Settings:        req.Settings,
		TenantID:        tenantID,
	}

	// Register the provider
	if err := h.registry.Register(r.Context(), config); err != nil {
		h.logger.Printf("[LLMProviderAPI] register error: %v", err)

		// Check if it's a license error
		if strings.Contains(err.Error(), "license") {
			h.writeError(w, http.StatusForbidden, "LICENSE_ERROR", err.Error())
			return
		}

		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to register provider")
		return
	}

	h.logger.Printf("[LLMProviderAPI] Created provider: %s (type: %s)", req.Name, req.Type)

	healthResult := h.registry.GetHealthResult(tenantID, req.Name)
	resource := toProviderResource(config, healthResult)

	h.writeJSON(w, http.StatusCreated, LLMProviderResponse{Provider: &resource})
}

// handleGetProviderMux handles GET /api/v1/llm-providers/{name}.
func (h *LLMProviderAPIHandler) handleGetProviderMux(w http.ResponseWriter, r *http.Request, providerName string) {
	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	// #3067 (S-3): naming another tenant's provider now yields the same 404 as
	// a nonexistent one, matching the disclosure posture the PUT/DELETE
	// siblings already had.
	config, err := h.registry.GetConfig(tenantID, providerName)
	if err != nil || config == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	healthResult := h.registry.GetHealthResult(tenantID, providerName)
	resource := toProviderResource(config, healthResult)

	h.writeJSON(w, http.StatusOK, LLMProviderResponse{Provider: &resource})
}

// handleUpdateProviderMux handles PUT /api/v1/llm-providers/{name}.
//
// v9 Phase 8 PR-C2 (#2384): require X-Tenant-ID/X-Org-ID + verify it matches
// the in-memory cfg's TenantID — same shape as DeleteProvider per #2384's
// cross-tenant write-authz audit. 404 on mismatch to avoid disclosure.
func (h *LLMProviderAPIHandler) handleUpdateProviderMux(w http.ResponseWriter, r *http.Request, providerName string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	// Mutation: the caller must OWN the provider. Deployment-level providers
	// and other tenants' both answer false, and both surface as 404.
	if !h.registry.OwnsProvider(tenantID, providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	var req UpdateLLMProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body")
		return
	}

	// Get existing config. OwnsProvider already proved the tenancy, so this
	// resolves the caller's own entry.
	config, err := h.registry.GetConfig(tenantID, providerName)
	if err != nil || config == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}
	if config.TenantID != tenantID {
		// Defence in depth: a config whose stored TenantID disagrees with the
		// key it was found under must never be updated under this tenancy.
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	// Update fields if provided
	if req.APIKey != nil {
		config.APIKey = *req.APIKey
	}
	if req.APIKeySecretARN != nil {
		config.APIKeySecretARN = *req.APIKeySecretARN
	}
	if req.Endpoint != nil {
		config.Endpoint = *req.Endpoint
	}
	if req.Model != nil {
		config.Model = *req.Model
	}
	if req.Region != nil {
		config.Region = *req.Region
	}
	if req.Enabled != nil {
		config.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		config.Priority = *req.Priority
	}
	if req.Weight != nil {
		config.Weight = *req.Weight
	}
	if req.RateLimit != nil {
		config.RateLimit = *req.RateLimit
	}
	if req.TimeoutSeconds != nil {
		config.TimeoutSeconds = *req.TimeoutSeconds
	}
	if req.Settings != nil {
		config.Settings = req.Settings
	}

	// Atomically update provider config in registry
	if err := h.registry.Update(r.Context(), config); err != nil {
		h.logger.Printf("[LLMProviderAPI] update error provider %s: %v", logutil.Sanitize(providerName), err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update provider")
		return
	}

	h.logger.Printf("[LLMProviderAPI] Updated provider: %s", providerName)

	healthResult := h.registry.GetHealthResult(tenantID, providerName)
	resource := toProviderResource(config, healthResult)

	h.writeJSON(w, http.StatusOK, LLMProviderResponse{Provider: &resource})
}

// handleDeleteProviderMux handles DELETE /api/v1/llm-providers/{name}.
//
// v9 Phase 8 PR-C2 (#2384): require X-Tenant-ID/X-Org-ID + verify it matches
// the in-memory cfg's TenantID before delegating to Unregister. Without this
// check, any caller could delete any provider by name — registry.Unregister
// pulls TenantID from the in-memory config and the RLS wrap would happily
// scope to it, succeeding cross-tenant. Returns 404 (not 403) on mismatch
// to avoid enumeration disclosure of which providers exist in which tenants.
func (h *LLMProviderAPIHandler) handleDeleteProviderMux(w http.ResponseWriter, r *http.Request, providerName string) {
	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	if !h.registry.OwnsProvider(tenantID, providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	cfg, getErr := h.registry.GetConfig(tenantID, providerName)
	if getErr != nil || cfg == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}
	if cfg.TenantID != tenantID {
		// Cross-tenant access attempt — surface as 404 to avoid disclosure.
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	if err := h.registry.Unregister(r.Context(), tenantID, providerName); err != nil {
		h.logger.Printf("[LLMProviderAPI] delete error provider %s: %v", providerName, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete provider")
		return
	}

	h.logger.Printf("[LLMProviderAPI] Deleted provider: %s", providerName)

	w.WriteHeader(http.StatusNoContent)
}

// handleProviderHealthMux handles GET /api/v1/llm-providers/{name}/health.
func (h *LLMProviderAPIHandler) handleProviderHealthMux(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	vars := mux.Vars(r)
	providerName := vars["name"]

	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	// Ownership, not visibility (R3): a health check is an outbound call on the
	// provider's credential and it writes the cached result the deployment
	// router selects on. Letting a tenant health-check the deployment's own
	// provider is both unmetered spend of the operator's key and a lever to
	// evict that provider from the routing pool for everyone.
	if !h.registry.OwnsProvider(tenantID, providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	result, err := h.registry.HealthCheckSingle(r.Context(), tenantID, providerName)
	if err != nil {
		h.logger.Printf("[LLMProviderAPI] health check error provider %s: %v", providerName, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to perform health check")
		return
	}

	h.writeJSON(w, http.StatusOK, LLMProviderHealthResponse{
		Name:   providerName,
		Health: result,
	})
}

// handleTestProvider handles POST /api/v1/llm-providers/{name}/test.
func (h *LLMProviderAPIHandler) handleTestProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	vars := mux.Vars(r)
	providerName := vars["name"]

	// #3067 (S-2, CRITICAL): authorize BEFORE resolving the provider, and
	// therefore before any upstream call. This endpoint used to look the
	// provider up by name in a flat map and run a completion through it —
	// spending and billing ANOTHER tenant's API key and returning them the
	// completion.
	//
	// Ownership, not mere visibility, is the gate here (R3): SPENDING a key is
	// mutation-grade, so unlike the read handlers this one does NOT fall back
	// to the deployment-global pool. Otherwise any tenant could run arbitrary
	// prompts through the operator's bootstrap provider — an ungoverned LLM
	// egress path on the deployment's own key. No credential is touched on
	// the refusal path.
	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	if !h.registry.OwnsProvider(tenantID, providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	provider, err := h.registry.Get(r.Context(), tenantID, providerName)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	// Parse optional test prompt from body
	var testReq struct {
		Prompt string `json:"prompt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&testReq); err != nil {
		testReq.Prompt = "Say 'Hello, AxonFlow!' in exactly 3 words."
	}
	if testReq.Prompt == "" {
		testReq.Prompt = "Say 'Hello, AxonFlow!' in exactly 3 words."
	}

	// Execute test request
	req := llm.CompletionRequest{
		Prompt:    testReq.Prompt,
		MaxTokens: 50,
	}

	resp, err := provider.Complete(r.Context(), req)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "TEST_FAILED", "test failed: "+logutil.Sanitize(err.Error()))
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"provider": providerName,
		"response": resp.Content,
		"model":    resp.Model,
		"usage": map[string]int{
			"prompt_tokens":     resp.Usage.PromptTokens,
			"completion_tokens": resp.Usage.CompletionTokens,
			"total_tokens":      resp.Usage.TotalTokens,
		},
		"latency_ms": resp.Latency.Milliseconds(),
	})
}

// handleRoutingMux handles GET/PUT /api/v1/llm-providers/routing.
func (h *LLMProviderAPIHandler) handleRoutingMux(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getRoutingConfigMux(w, r)
	case http.MethodPut:
		h.updateRoutingConfigMux(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

// getRoutingConfigMux handles GET /api/v1/llm-providers/routing.
func (h *LLMProviderAPIHandler) getRoutingConfigMux(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	// Build weights from the providers this tenant OWNS (#3067 S-3).
	//
	// This must list exactly the set updateRoutingConfigMux accepts (R3):
	// listing deployment-level providers here while the PUT gates on
	// ownership breaks read-modify-write — a client echoing back what it
	// just read would get 400 "provider not found".
	weights := make(map[string]int)
	for _, name := range h.registry.List(tenantID) {
		if !h.registry.OwnsProvider(tenantID, name) {
			continue
		}
		config, err := h.registry.GetConfig(tenantID, name)
		if err == nil && config != nil {
			weights[name] = config.Weight
		}
	}

	h.writeJSON(w, http.StatusOK, LLMRoutingConfigResponse{
		Weights: weights,
	})
}

// updateRoutingConfigMux handles PUT /api/v1/llm-providers/routing.
func (h *LLMProviderAPIHandler) updateRoutingConfigMux(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	var req UpdateLLMRoutingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body")
		return
	}

	// Update weights for each provider the caller OWNS. #3067 (S-3): PUT
	// /routing used to write straight through to another tenant's row via
	// Registry.Update -> storage.SaveProvider, silently disabling their LLM
	// routing. Deployment-level providers are equally off-limits here.
	for name, weight := range req.Weights {
		if !h.registry.OwnsProvider(tenantID, name) {
			h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "provider not found: "+logutil.Sanitize(name))
			return
		}

		config, err := h.registry.GetConfig(tenantID, name)
		if err != nil {
			h.logger.Printf("[LLMProviderAPI] get config error provider %s: %v", name, err)
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get provider config")
			return
		}
		if config != nil {
			config.Weight = weight
			if err := h.registry.Update(r.Context(), config); err != nil {
				h.logger.Printf("[LLMProviderAPI] update routing error provider %s: %v", name, err)
				h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update routing")
				return
			}
		}
	}

	h.logger.Printf("[LLMProviderAPI] Updated routing for %d providers", len(req.Weights))

	// Return updated config
	h.getRoutingConfigMux(w, r)
}

// handleAllProvidersStatusMux handles GET /api/v1/llm-providers/status.
func (h *LLMProviderAPIHandler) handleAllProvidersStatusMux(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID, ok := h.requireTenantID(w, r)
	if !ok {
		return
	}

	// Perform health check on the providers this tenant can see (#3067 S-3):
	// this used to health-check every tenant's provider and return every
	// result keyed by name.
	h.registry.HealthCheck(r.Context(), tenantID)

	// Collect results
	results := make(map[string]*llm.HealthCheckResult)
	for _, name := range h.registry.List(tenantID) {
		results[name] = h.registry.GetHealthResult(tenantID, name)
	}

	h.writeJSON(w, http.StatusOK, LLMProviderHealthAllResponse{
		Providers: results,
	})
}

// handleListProviderTypes handles GET /api/v1/llm-provider-types.
func (h *LLMProviderAPIHandler) handleListProviderTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	factories := llm.ListFactories()

	types := make([]map[string]interface{}, 0, len(factories))
	for _, pt := range factories {
		info := map[string]interface{}{
			"type":      string(pt),
			"community": llm.IsCommunityProvider(pt),
		}

		// Add tier info
		tier := llm.GetTierForProvider(pt)
		info["required_tier"] = string(tier)

		types = append(types, info)
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"provider_types": types,
		"count":          len(types),
	})
}

// Helper methods

// handleCORS handles OPTIONS preflight requests.
// Note: The main router uses github.com/rs/cors middleware which handles CORS globally.
// This handler is kept for explicit OPTIONS method handling in route registration.
func (h *LLMProviderAPIHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-User-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func (h *LLMProviderAPIHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *LLMProviderAPIHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, LLMProviderAPIError{
		Error: LLMProviderAPIErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// toProviderResource converts ProviderConfig to API resource.
func toProviderResource(config *llm.ProviderConfig, health *llm.HealthCheckResult) LLMProviderResource {
	resource := LLMProviderResource{
		Name:           config.Name,
		Type:           string(config.Type),
		Endpoint:       config.Endpoint,
		Model:          config.Model,
		Region:         config.Region,
		Enabled:        config.Enabled,
		Priority:       config.Priority,
		Weight:         config.Weight,
		RateLimit:      config.RateLimit,
		TimeoutSeconds: config.TimeoutSeconds,
		HasAPIKey:      config.APIKey != "" || config.APIKeySecretARN != "",
		Settings:       config.Settings,
	}

	if health != nil {
		resource.Health = &LLMProviderHealthInfo{
			Status:      string(health.Status),
			Message:     health.Message,
			LastChecked: health.LastChecked,
		}
	}

	return resource
}
