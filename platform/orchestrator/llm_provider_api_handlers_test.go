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
