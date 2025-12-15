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

	// Get all provider names from registry
	names := h.registry.List()

	// Apply filters and build response
	providers := make([]LLMProviderResource, 0, len(names))
	for _, name := range names {
		provider, err := h.registry.Get(r.Context(), name)
		if err != nil {
			continue
		}

		// Type filter
		if params.Type != "" && provider.Type() != params.Type {
			continue
		}

		// Get config from registry
		config, err := h.registry.GetConfig(name)
		if err != nil || config == nil {
			continue
		}

		// Enabled filter
		if params.Enabled != nil && config.Enabled != *params.Enabled {
			continue
		}

		healthResult := h.registry.GetHealthResult(name)
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

	// Check if provider already exists
	if h.registry.Has(req.Name) {
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

	healthResult := h.registry.GetHealthResult(req.Name)
	resource := toProviderResource(config, healthResult)

	h.writeJSON(w, http.StatusCreated, LLMProviderResponse{Provider: &resource})
}

// handleGetProviderMux handles GET /api/v1/llm-providers/{name}.
func (h *LLMProviderAPIHandler) handleGetProviderMux(w http.ResponseWriter, r *http.Request, providerName string) {
	if !h.registry.Has(providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	config, err := h.registry.GetConfig(providerName)
	if err != nil || config == nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	healthResult := h.registry.GetHealthResult(providerName)
	resource := toProviderResource(config, healthResult)

	h.writeJSON(w, http.StatusOK, LLMProviderResponse{Provider: &resource})
}

// handleUpdateProviderMux handles PUT /api/v1/llm-providers/{name}.
func (h *LLMProviderAPIHandler) handleUpdateProviderMux(w http.ResponseWriter, r *http.Request, providerName string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	if !h.registry.Has(providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	var req UpdateLLMProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body")
		return
	}

	// Get existing config
	config, err := h.registry.GetConfig(providerName)
	if err != nil || config == nil {
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

	// Update in registry by unregister + re-register
	if err := h.registry.Unregister(r.Context(), providerName); err != nil {
		h.logger.Printf("[LLMProviderAPI] update error (unregister) provider %s: %v", providerName, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update provider")
		return
	}
	if err := h.registry.Register(r.Context(), config); err != nil {
		h.logger.Printf("[LLMProviderAPI] update error (register) provider %s: %v", providerName, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update provider")
		return
	}

	h.logger.Printf("[LLMProviderAPI] Updated provider: %s", providerName)

	healthResult := h.registry.GetHealthResult(providerName)
	resource := toProviderResource(config, healthResult)

	h.writeJSON(w, http.StatusOK, LLMProviderResponse{Provider: &resource})
}

// handleDeleteProviderMux handles DELETE /api/v1/llm-providers/{name}.
func (h *LLMProviderAPIHandler) handleDeleteProviderMux(w http.ResponseWriter, r *http.Request, providerName string) {
	if !h.registry.Has(providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	if err := h.registry.Unregister(r.Context(), providerName); err != nil {
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

	if !h.registry.Has(providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	result, err := h.registry.HealthCheckSingle(r.Context(), providerName)
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

	provider, err := h.registry.Get(r.Context(), providerName)
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
		h.writeError(w, http.StatusInternalServerError, "TEST_FAILED", "test failed: "+err.Error())
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
	// Build weights from provider configs
	weights := make(map[string]int)
	for _, name := range h.registry.List() {
		config, err := h.registry.GetConfig(name)
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

	var req UpdateLLMRoutingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body")
		return
	}

	// Update weights for each provider
	for name, weight := range req.Weights {
		if !h.registry.Has(name) {
			h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "provider not found: "+name)
			return
		}

		config, err := h.registry.GetConfig(name)
		if err != nil {
			h.logger.Printf("[LLMProviderAPI] get config error provider %s: %v", name, err)
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get provider config")
			return
		}
		if config != nil {
			config.Weight = weight
			// Registry doesn't have Update - must unregister and re-register
			if err := h.registry.Unregister(r.Context(), name); err != nil {
				h.logger.Printf("[LLMProviderAPI] unregister error provider %s: %v", name, err)
				h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update routing")
				return
			}
			if err := h.registry.Register(r.Context(), config); err != nil {
				h.logger.Printf("[LLMProviderAPI] re-register error provider %s: %v", name, err)
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

	// Perform health check on all providers
	h.registry.HealthCheck(r.Context())

	// Collect results
	results := make(map[string]*llm.HealthCheckResult)
	for _, name := range h.registry.List() {
		results[name] = h.registry.GetHealthResult(name)
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
			"type": string(pt),
			"oss":  llm.IsOSSProvider(pt),
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
