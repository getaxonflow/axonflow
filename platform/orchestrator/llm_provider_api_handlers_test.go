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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"axonflow/platform/orchestrator/llm"
)

func TestLLMProviderAPIHandler_ListProviders(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)

	t.Run("returns empty list when no providers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp LLMProviderListResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(resp.Providers) != 0 {
			t.Errorf("expected 0 providers, got %d", len(resp.Providers))
		}
	})

	t.Run("returns unauthorized without tenant ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers", nil)
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("returns providers after registration", func(t *testing.T) {
		// Register a provider
		config := &llm.ProviderConfig{
			Name:    "test-openai",
			Type:    llm.ProviderTypeOpenAI,
			APIKey:  "test-key",
			Enabled: true,
		}
		if err := registry.Register(context.Background(), config); err != nil {
			t.Fatalf("failed to register provider: %v", err)
		}
		defer registry.Unregister(context.Background(), "test-openai")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp LLMProviderListResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(resp.Providers) != 1 {
			t.Errorf("expected 1 provider, got %d", len(resp.Providers))
		}
	})
}

func TestLLMProviderAPIHandler_CreateProvider(t *testing.T) {
	t.Run("creates provider successfully", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		body := CreateLLMProviderRequest{
			Name:    "new-provider",
			Type:    "openai",
			APIKey:  "test-key",
			Enabled: true,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		var resp LLMProviderResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Provider.Name != "new-provider" {
			t.Errorf("expected name 'new-provider', got %q", resp.Provider.Name)
		}
	})

	t.Run("rejects missing name", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		body := CreateLLMProviderRequest{
			Type:   "openai",
			APIKey: "test-key",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("rejects invalid provider type", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		body := CreateLLMProviderRequest{
			Name:   "test-provider",
			Type:   "invalid-type",
			APIKey: "test-key",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		var errResp LLMProviderAPIError
		if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}

		if errResp.Error.Code != "VALIDATION_ERROR" {
			t.Errorf("expected error code 'VALIDATION_ERROR', got %q", errResp.Error.Code)
		}
	})

	t.Run("rejects duplicate provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		// Register first provider
		config := &llm.ProviderConfig{
			Name:   "existing-provider",
			Type:   llm.ProviderTypeOpenAI,
			APIKey: "test-key",
		}
		registry.Register(context.Background(), config)

		body := CreateLLMProviderRequest{
			Name:   "existing-provider",
			Type:   "openai",
			APIKey: "test-key",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_GetProvider(t *testing.T) {
	t.Run("returns provider by name", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		config := &llm.ProviderConfig{
			Name:    "get-test-provider",
			Type:    llm.ProviderTypeAnthropic,
			APIKey:  "test-key",
			Enabled: true,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), "get-test-provider")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/get-test-provider", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp LLMProviderResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Provider.Name != "get-test-provider" {
			t.Errorf("expected name 'get-test-provider', got %q", resp.Provider.Name)
		}
	})

	t.Run("returns 404 for non-existent provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/non-existent", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_DeleteProvider(t *testing.T) {
	t.Run("deletes provider successfully", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		config := &llm.ProviderConfig{
			Name:   "delete-test-provider",
			Type:   llm.ProviderTypeOllama,
		}
		registry.Register(context.Background(), config)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/llm-providers/delete-test-provider", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
		}

		// Verify deletion
		if registry.Has("delete-test-provider") {
			t.Error("provider should have been deleted")
		}
	})

	t.Run("returns 404 for non-existent provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/llm-providers/non-existent", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_HealthCheck(t *testing.T) {
	t.Run("returns health for single provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		config := &llm.ProviderConfig{
			Name:   "health-test-provider",
			Type:   llm.ProviderTypeOllama,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), "health-test-provider")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/health-test-provider/health", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp LLMProviderHealthResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Name != "health-test-provider" {
			t.Errorf("expected name 'health-test-provider', got %q", resp.Name)
		}
	})

	t.Run("returns health for all providers", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		config := &llm.ProviderConfig{
			Name: "health-all-test",
			Type: llm.ProviderTypeOllama,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), "health-all-test")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/health", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleHealthAll(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp LLMProviderHealthAllResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(resp.Providers) != 1 {
			t.Errorf("expected 1 provider, got %d", len(resp.Providers))
		}
	})
}

func TestIsValidProviderType(t *testing.T) {
	tests := []struct {
		name     string
		input    llm.ProviderType
		expected bool
	}{
		{"anthropic", llm.ProviderTypeAnthropic, true},
		{"openai", llm.ProviderTypeOpenAI, true},
		{"ollama", llm.ProviderTypeOllama, true},
		{"bedrock", llm.ProviderTypeBedrock, true},
		{"custom", llm.ProviderTypeCustom, true},
		{"invalid", llm.ProviderType("invalid"), false},
		{"empty", llm.ProviderType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidProviderType(tt.input)
			if result != tt.expected {
				t.Errorf("isValidProviderType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLLMProviderAPIHandler_UpdateProvider(t *testing.T) {
	t.Run("updates provider successfully", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		// Register provider first
		config := &llm.ProviderConfig{
			Name:    "update-test",
			Type:    llm.ProviderTypeOpenAI,
			APIKey:  "original-key",
			Enabled: true,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), "update-test")

		newKey := "updated-key"
		enabled := false
		body := UpdateLLMProviderRequest{
			APIKey:  &newKey,
			Enabled: &enabled,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/update-test", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("returns 404 for non-existent provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		newKey := "new-key"
		body := UpdateLLMProviderRequest{
			APIKey: &newKey,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/non-existent", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_Routing(t *testing.T) {
	t.Run("get routing config", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		config := &llm.ProviderConfig{
			Name:    "routing-test",
			Type:    llm.ProviderTypeOllama, // Use Ollama - doesn't require API key
			Weight:  50,
			Enabled: true,
		}
		if err := registry.Register(context.Background(), config); err != nil {
			t.Fatalf("failed to register provider: %v", err)
		}
		defer registry.Unregister(context.Background(), "routing-test")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/routing", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleRouting(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp LLMRoutingConfigResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Weight should be present in the response
		if _, ok := resp.Weights["routing-test"]; !ok {
			t.Error("expected routing-test in weights response")
		}
	})

	t.Run("update routing config", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		config := &llm.ProviderConfig{
			Name:    "routing-update-test",
			Type:    llm.ProviderTypeOllama,
			Weight:  5,
			Enabled: true,
		}
		if err := registry.Register(context.Background(), config); err != nil {
			t.Fatalf("failed to register provider: %v", err)
		}
		defer registry.Unregister(context.Background(), "routing-update-test")

		body := UpdateLLMRoutingRequest{
			Weights: map[string]int{"routing-update-test": 20},
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/routing", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleRouting(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("routing requires tenant ID", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/routing", nil)
		w := httptest.NewRecorder()

		handler.handleRouting(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_RegisterRoutes(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)
	mux := http.NewServeMux()

	// Should not panic
	handler.RegisterRoutes(mux)

	// Test that routes are registered by making a request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	// Should get a valid response (200), not 404
	if w.Code == http.StatusNotFound {
		t.Error("routes were not registered properly")
	}
}

func TestLLMProviderAPIHandler_MethodNotAllowed(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/llm-providers", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.handleProviders(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestLLMProviderAPIHandler_CORS(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/llm-providers", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.handleProviders(w, req)

	// CORS preflight should return 200 or 204
	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Errorf("expected status 200 or 204 for CORS preflight, got %d", w.Code)
	}
}

func TestLLMProviderAPIHandler_ProviderByName_SpecialPaths(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)

	t.Run("handles health path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/health", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		// Should not return 404 (health endpoint exists)
		if w.Code == http.StatusNotFound {
			t.Error("health endpoint should not return 404")
		}
	})

	t.Run("handles routing path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/routing", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		// Should return 200 (routing endpoint exists)
		if w.Code != http.StatusOK {
			t.Errorf("routing endpoint should return 200, got %d", w.Code)
		}
	})

	t.Run("handles empty provider name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		// Should return bad request for empty name
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d for empty name, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("handles OPTIONS for provider by name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/llm-providers/some-provider", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d for OPTIONS, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("handles provider health check subpath", func(t *testing.T) {
		// Register a test provider
		config := &llm.ProviderConfig{
			Name:    "health-subpath-test",
			Type:    llm.ProviderTypeOllama,
			Enabled: true,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), "health-subpath-test")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/health-subpath-test/health", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviderByName(w, req)

		// Should return 200 for individual provider health
		if w.Code != http.StatusOK {
			t.Errorf("expected status %d for provider health check, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})
}

func TestLLMProviderAPIHandler_UpdateRoutingConfig_Errors(t *testing.T) {
	t.Run("returns error for non-existent provider in weights", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		body := UpdateLLMRoutingRequest{
			Weights: map[string]int{"non-existent-provider": 10},
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/routing", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleRouting(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d for non-existent provider, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/routing", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleRouting(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d for invalid JSON, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("returns method not allowed for unsupported methods", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/llm-providers/routing", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleRouting(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d for DELETE on routing, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_ListProviders_Filters(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)

	// Register test providers
	config1 := &llm.ProviderConfig{
		Name:    "filter-test-1",
		Type:    llm.ProviderTypeOllama,
		Enabled: true,
	}
	config2 := &llm.ProviderConfig{
		Name:    "filter-test-2",
		Type:    llm.ProviderTypeAnthropic,
		APIKey:  "test-key",
		Enabled: false,
	}
	registry.Register(context.Background(), config1)
	registry.Register(context.Background(), config2)
	defer registry.Unregister(context.Background(), "filter-test-1")
	defer registry.Unregister(context.Background(), "filter-test-2")

	t.Run("filter by type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers?type=ollama", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("filter by enabled status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers?enabled=true", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("custom pagination", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers?page=2&page_size=1", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp LLMProviderListResponse
		json.NewDecoder(w.Body).Decode(&resp)

		if resp.Pagination.Page != 2 {
			t.Errorf("expected page 2, got %d", resp.Pagination.Page)
		}
	})
}

func TestLLMProviderAPIHandler_CreateProvider_Validation(t *testing.T) {
	t.Run("rejects missing type", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		body := CreateLLMProviderRequest{
			Name:   "missing-type",
			APIKey: "test-key",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d for missing type, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader([]byte("{invalid")))
		req.Header.Set("X-Tenant-ID", "test-tenant")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleProviders(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d for invalid JSON, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_HealthAllProviders(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)

	// Register a test provider
	config := &llm.ProviderConfig{
		Name:    "health-all-provider",
		Type:    llm.ProviderTypeOllama,
		Enabled: true,
	}
	registry.Register(context.Background(), config)
	defer registry.Unregister(context.Background(), "health-all-provider")

	t.Run("returns health for all providers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/health", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleHealthAll(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("requires tenant ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/health", nil)
		w := httptest.NewRecorder()

		handler.handleHealthAll(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d without tenant, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("returns method not allowed for POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers/health", nil)
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		handler.handleHealthAll(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d for POST, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})
}
