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
	"log"
	"net/http"
	"strconv"
	"strings"

	"axonflow/platform/orchestrator/llm"
)

// LLMProviderAPIHandler handles HTTP requests for LLM provider management.
// Note: tenantID is extracted and logged for future multi-tenancy support,
// but filtering by tenant is not yet implemented in the registry.
type LLMProviderAPIHandler struct {
	registry *llm.Registry
	router   *llm.Router
}

// NewLLMProviderAPIHandler creates a new LLM provider API handler.
func NewLLMProviderAPIHandler(registry *llm.Registry, router *llm.Router) *LLMProviderAPIHandler {
	return &LLMProviderAPIHandler{
		registry: registry,
		router:   router,
	}
}

// RegisterRoutes registers LLM provider API routes with the provided mux.
func (h *LLMProviderAPIHandler) RegisterRoutes(mux *http.ServeMux) {
	// Provider CRUD endpoints
	mux.HandleFunc("/api/v1/llm-providers", h.handleProviders)
	mux.HandleFunc("/api/v1/llm-providers/", h.handleProviderByName)

	// Health endpoints
	mux.HandleFunc("/api/v1/llm-providers/health", h.handleHealthAll)

	// Routing configuration
	mux.HandleFunc("/api/v1/llm-providers/routing", h.handleRouting)
}

// handleProviders handles GET (list) and POST (create) for /api/v1/llm-providers.
func (h *LLMProviderAPIHandler) handleProviders(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing tenant ID")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listProviders(w, r, tenantID)
	case http.MethodPost:
		h.createProvider(w, r, tenantID)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

// handleProviderByName handles individual provider operations.
func (h *LLMProviderAPIHandler) handleProviderByName(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing tenant ID")
		return
	}

	// Extract provider name and subpath from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/llm-providers/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "provider name is required")
		return
	}

	providerName := parts[0]

	// Handle special paths
	if providerName == "health" {
		h.handleHealthAll(w, r)
		return
	}
	if providerName == "routing" {
		h.handleRouting(w, r)
		return
	}

	subpath := ""
	if len(parts) > 1 {
		subpath = parts[1]
	}

	switch {
	case subpath == "health" && r.Method == http.MethodGet:
		h.healthCheckProvider(w, r, tenantID, providerName)
	case subpath == "" && r.Method == http.MethodGet:
		h.getProvider(w, r, tenantID, providerName)
	case subpath == "" && r.Method == http.MethodPut:
		h.updateProvider(w, r, tenantID, providerName)
	case subpath == "" && r.Method == http.MethodDelete:
		h.deleteProvider(w, r, tenantID, providerName)
	case r.Method == http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

// listProviders handles GET /api/v1/llm-providers.
func (h *LLMProviderAPIHandler) listProviders(w http.ResponseWriter, r *http.Request, tenantID string) {
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

// createProvider handles POST /api/v1/llm-providers.
func (h *LLMProviderAPIHandler) createProvider(w http.ResponseWriter, r *http.Request, tenantID string) {
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

	// Validate provider type
	providerType := llm.ProviderType(req.Type)
	if !isValidProviderType(providerType) {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid provider type: "+req.Type)
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
		Type:            llm.ProviderType(req.Type),
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
		log.Printf("[LLMProviderAPI] register error for tenant %s: %v", tenantID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to register provider")
		return
	}

	healthResult := h.registry.GetHealthResult(req.Name)
	resource := toProviderResource(config, healthResult)

	h.writeJSON(w, http.StatusCreated, LLMProviderResponse{Provider: &resource})
}

// getProvider handles GET /api/v1/llm-providers/{name}.
func (h *LLMProviderAPIHandler) getProvider(w http.ResponseWriter, r *http.Request, tenantID, providerName string) {
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

// updateProvider handles PUT /api/v1/llm-providers/{name}.
func (h *LLMProviderAPIHandler) updateProvider(w http.ResponseWriter, r *http.Request, tenantID, providerName string) {
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
		log.Printf("[LLMProviderAPI] update error (unregister) for tenant %s, provider %s: %v", tenantID, providerName, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update provider")
		return
	}
	if err := h.registry.Register(r.Context(), config); err != nil {
		log.Printf("[LLMProviderAPI] update error (register) for tenant %s, provider %s: %v", tenantID, providerName, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update provider")
		return
	}

	healthResult := h.registry.GetHealthResult(providerName)
	resource := toProviderResource(config, healthResult)

	h.writeJSON(w, http.StatusOK, LLMProviderResponse{Provider: &resource})
}

// deleteProvider handles DELETE /api/v1/llm-providers/{name}.
func (h *LLMProviderAPIHandler) deleteProvider(w http.ResponseWriter, r *http.Request, tenantID, providerName string) {
	if !h.registry.Has(providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	if err := h.registry.Unregister(r.Context(), providerName); err != nil {
		log.Printf("[LLMProviderAPI] delete error for tenant %s, provider %s: %v", tenantID, providerName, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete provider")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// healthCheckProvider handles GET /api/v1/llm-providers/{name}/health.
func (h *LLMProviderAPIHandler) healthCheckProvider(w http.ResponseWriter, r *http.Request, tenantID, providerName string) {
	if !h.registry.Has(providerName) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "provider not found")
		return
	}

	result, err := h.registry.HealthCheckSingle(r.Context(), providerName)
	if err != nil {
		log.Printf("[LLMProviderAPI] health check error for tenant %s, provider %s: %v", tenantID, providerName, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to perform health check")
		return
	}

	h.writeJSON(w, http.StatusOK, LLMProviderHealthResponse{
		Name:   providerName,
		Health: result,
	})
}

// handleHealthAll handles GET /api/v1/llm-providers/health.
func (h *LLMProviderAPIHandler) handleHealthAll(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing tenant ID")
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

// handleRouting handles PUT /api/v1/llm-providers/routing.
func (h *LLMProviderAPIHandler) handleRouting(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing tenant ID")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getRoutingConfig(w, r, tenantID)
	case http.MethodPut:
		h.updateRoutingConfig(w, r, tenantID)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

// getRoutingConfig handles GET /api/v1/llm-providers/routing.
func (h *LLMProviderAPIHandler) getRoutingConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
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

// updateRoutingConfig handles PUT /api/v1/llm-providers/routing.
func (h *LLMProviderAPIHandler) updateRoutingConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
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
			log.Printf("[LLMProviderAPI] get config error for tenant %s, provider %s: %v", tenantID, name, err)
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get provider config")
			return
		}
		if config != nil {
			config.Weight = weight
			// Registry doesn't have Update - must unregister and re-register
			if err := h.registry.Unregister(r.Context(), name); err != nil {
				log.Printf("[LLMProviderAPI] unregister error for tenant %s, provider %s: %v", tenantID, name, err)
				h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update routing")
				return
			}
			if err := h.registry.Register(r.Context(), config); err != nil {
				log.Printf("[LLMProviderAPI] re-register error for tenant %s, provider %s: %v", tenantID, name, err)
				h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update routing")
				return
			}
		}
	}

	// Return updated config
	h.getRoutingConfig(w, r, tenantID)
}

// Helper methods

func (h *LLMProviderAPIHandler) getTenantID(r *http.Request) string {
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}
	if tenantID, ok := r.Context().Value("tenant_id").(string); ok {
		return tenantID
	}
	return ""
}

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

// isValidProviderType checks if the provider type is a known valid type.
func isValidProviderType(t llm.ProviderType) bool {
	switch t {
	case llm.ProviderTypeAnthropic,
		llm.ProviderTypeOpenAI,
		llm.ProviderTypeOllama,
		llm.ProviderTypeBedrock,
		llm.ProviderTypeCustom:
		return true
	default:
		return false
	}
}

// toProviderResource converts ProviderConfig to API resource.
func toProviderResource(config *llm.ProviderConfig, health *llm.HealthCheckResult) LLMProviderResource {
	resource := LLMProviderResource{
		Name:            config.Name,
		Type:            string(config.Type),
		Endpoint:        config.Endpoint,
		Model:           config.Model,
		Region:          config.Region,
		Enabled:         config.Enabled,
		Priority:        config.Priority,
		Weight:          config.Weight,
		RateLimit:       config.RateLimit,
		TimeoutSeconds:  config.TimeoutSeconds,
		HasAPIKey:       config.APIKey != "" || config.APIKeySecretARN != "",
		Settings:        config.Settings,
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
