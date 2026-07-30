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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/llm"
)

// testProviderTenant is the tenancy the provider-API tests operate under.
// #3067 keyed the LLM registry by tenant and made every read handler require
// an asserted tenancy, so a test provider must be registered under a tenant
// and the request must carry the header the agent's auth chain stamps.
const testProviderTenant = "test-tenant"

// withTenant stamps the authenticated-tenant header the orchestrator sees
// after apiAuthMiddleware has overwritten any client-supplied value.
func withTenant(req *http.Request, tenantID string) *http.Request {
	req.Header.Set("X-Tenant-ID", tenantID)
	return req
}

// createTestRouter creates a mux.Router with the LLM provider API routes registered
func createTestRouter(handler *LLMProviderAPIHandler) *mux.Router {
	r := mux.NewRouter()
	handler.RegisterRoutesWithMux(r)
	return r
}

func TestNewLLMProviderAPIHandlerWithRouter(t *testing.T) {
	t.Run("returns nil for nil router", func(t *testing.T) {
		handler := NewLLMProviderAPIHandlerWithRouter(nil, nil)
		if handler != nil {
			t.Error("expected nil handler for nil router")
		}
	})

	t.Run("creates handler with valid router", func(t *testing.T) {
		registry := llm.NewRegistry()
		router := llm.NewRouter(llm.WithRouterRegistry(registry))
		handler := NewLLMProviderAPIHandlerWithRouter(router, nil)
		if handler == nil {
			t.Error("expected non-nil handler")
		}
		if handler.registry != registry {
			t.Error("handler registry should match router registry")
		}
	})
}

func TestLLMProviderAPIHandler_CORS(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)
	router := createTestRouter(handler)

	t.Run("OPTIONS request returns CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/llm-providers", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		if w.Header().Get("Access-Control-Allow-Methods") == "" {
			t.Error("expected Access-Control-Allow-Methods header")
		}
	})

	t.Run("OPTIONS on provider endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/llm-providers/test-provider", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("OPTIONS on routing endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/llm-providers/routing", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_ProviderHealth(t *testing.T) {
	t.Run("returns 404 for non-existent provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/non-existent/health", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("returns health for existing provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		// Register a test provider
		config := &llm.ProviderConfig{
			Name:     "health-test-provider",
			TenantID: testProviderTenant,
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-key",
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), testProviderTenant, "health-test-provider")

		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/health-test-provider/health", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Health check will fail (no real API) but endpoint should work
		if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d or %d, got %d", http.StatusOK, http.StatusInternalServerError, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_MethodNotAllowed(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)
	router := createTestRouter(handler)

	t.Run("PATCH on providers returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/llm-providers", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// gorilla/mux returns 405 for unregistered methods
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_StatusEndpoint(t *testing.T) {
	t.Run("returns status for all providers", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		// Register a test provider
		config := &llm.ProviderConfig{
			Name:     "status-test-provider",
			TenantID: testProviderTenant,
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-key",
			Enabled:  true,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), testProviderTenant, "status-test-provider")

		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/status", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if _, ok := resp["providers"]; !ok {
			t.Error("expected 'providers' field in response")
		}
	})

	t.Run("OPTIONS on status endpoint", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		req := httptest.NewRequest(http.MethodOptions, "/api/v1/llm-providers/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_HealthEndpointOptions(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)
	router := createTestRouter(handler)

	// Register a test provider
	config := &llm.ProviderConfig{
		Name:     "options-health-provider",
		TenantID: testProviderTenant,
		Type:     llm.ProviderTypeOpenAI,
		APIKey:   "test-key",
	}
	registry.Register(context.Background(), config)
	defer registry.Unregister(context.Background(), testProviderTenant, "options-health-provider")

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/llm-providers/options-health-provider/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestLLMProviderAPIHandler_ListProviders(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)
	router := createTestRouter(handler)

	t.Run("returns empty list when no providers", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

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

	t.Run("returns providers after registration", func(t *testing.T) {
		// Register a provider
		config := &llm.ProviderConfig{
			Name:     "test-openai",
			TenantID: testProviderTenant,
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-key",
			Enabled:  true,
		}
		if err := registry.Register(context.Background(), config); err != nil {
			t.Fatalf("failed to register provider: %v", err)
		}
		defer registry.Unregister(context.Background(), testProviderTenant, "test-openai")

		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

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
		router := createTestRouter(handler)

		body := CreateLLMProviderRequest{
			Name:    "new-provider",
			Type:    "openai",
			APIKey:  "test-key",
			Enabled: true,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", "test-tenant")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

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

	t.Run("rejects missing tenant identity", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		body := CreateLLMProviderRequest{
			Name:    "new-provider-no-tenant",
			Type:    "openai",
			APIKey:  "test-key",
			Enabled: true,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		// Intentionally omit X-Tenant-ID + X-Org-ID
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
		}
	})

	t.Run("rejects missing name", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		body := CreateLLMProviderRequest{
			Type:   "openai",
			APIKey: "test-key",
		}
		bodyBytes, _ := json.Marshal(body)

		req := withTenant(httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes)), testProviderTenant)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("rejects invalid provider type", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		body := CreateLLMProviderRequest{
			Name:   "test-provider",
			Type:   "invalid-type",
			APIKey: "test-key",
		}
		bodyBytes, _ := json.Marshal(body)

		req := withTenant(httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes)), testProviderTenant)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

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
		router := createTestRouter(handler)

		// Register first provider
		config := &llm.ProviderConfig{
			Name:     "existing-provider",
			TenantID: testProviderTenant,
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-key",
		}
		registry.Register(context.Background(), config)

		body := CreateLLMProviderRequest{
			Name:   "existing-provider",
			Type:   "openai",
			APIKey: "test-key",
		}
		bodyBytes, _ := json.Marshal(body)

		req := withTenant(httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers", bytes.NewReader(bodyBytes)), testProviderTenant)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_GetProvider(t *testing.T) {
	t.Run("returns provider by name", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		config := &llm.ProviderConfig{
			Name:     "get-test-provider",
			TenantID: testProviderTenant,
			Type:     llm.ProviderTypeAnthropic,
			APIKey:   "test-key",
			Enabled:  true,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), testProviderTenant, "get-test-provider")

		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/get-test-provider", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

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
		router := createTestRouter(handler)

		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/non-existent", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_DeleteProvider(t *testing.T) {
	t.Run("deletes provider successfully", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		config := &llm.ProviderConfig{
			Name:     "delete-test-provider",
			TenantID: "tenant-x",
			Type:     llm.ProviderTypeOllama,
		}
		registry.Register(context.Background(), config)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/llm-providers/delete-test-provider", nil)
		// v9 Phase 8 PR-C2 (#2384): handler requires X-Tenant-ID/X-Org-ID +
		// must match the in-memory config's TenantID for cross-tenant authz.
		req.Header.Set("X-Tenant-ID", "tenant-x")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
		}

		// Verify deletion
		if registry.Has("tenant-x", "delete-test-provider") {
			t.Error("provider should have been deleted")
		}
	})

	t.Run("returns 404 for non-existent provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/llm-providers/non-existent", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("rejects cross-tenant delete with 404 (no disclosure)", func(t *testing.T) {
		// v9 Phase 8 PR-C2 (#2384): caller A cannot delete caller B's provider
		// even with knowledge of the name. The handler returns 404 (not 403) to
		// avoid disclosing which providers exist in which tenants.
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		config := &llm.ProviderConfig{
			Name:     "tenant-b-provider",
			TenantID: "tenant-B",
			Type:     llm.ProviderTypeOllama,
		}
		registry.Register(context.Background(), config)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/llm-providers/tenant-b-provider", nil)
		req.Header.Set("X-Tenant-ID", "tenant-A") // wrong tenant
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d (cross-tenant masked as 404), got %d", http.StatusNotFound, w.Code)
		}
		// Provider must still exist in the registry — cross-tenant DELETE is a no-op.
		if !registry.Has("tenant-B", "tenant-b-provider") {
			t.Error("cross-tenant DELETE should NOT have removed the provider")
		}
	})

	t.Run("rejects missing tenant header with 400", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/llm-providers/any-name", nil)
		// Intentionally no X-Tenant-ID or X-Org-ID
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_UpdateProvider(t *testing.T) {
	t.Run("updates provider successfully", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		// Create initial provider
		config := &llm.ProviderConfig{
			Name:     "update-test-provider",
			TenantID: "tenant-x",
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "original-key",
			Enabled:  false,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), "tenant-x", "update-test-provider")

		enabled := true
		body := UpdateLLMProviderRequest{
			Enabled: &enabled,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/update-test-provider", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", "tenant-x")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp LLMProviderResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if !resp.Provider.Enabled {
			t.Error("expected provider to be enabled after update")
		}
	})

	t.Run("rejects cross-tenant update with 404", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		config := &llm.ProviderConfig{
			Name:     "tenant-b-provider-update",
			TenantID: "tenant-B",
			Type:     llm.ProviderTypeOpenAI,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), "tenant-B", "tenant-b-provider-update")

		enabled := true
		body := UpdateLLMProviderRequest{Enabled: &enabled}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/tenant-b-provider-update", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", "tenant-A") // wrong tenant
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d (cross-tenant masked as 404), got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("returns 404 for non-existent provider", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		enabled := true
		body := UpdateLLMProviderRequest{
			Enabled: &enabled,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/non-existent", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", "tenant-x")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestLLMProviderAPIHandler_ProviderTypes(t *testing.T) {
	t.Run("returns available provider types", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/llm-provider-types", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		types, ok := resp["provider_types"].([]interface{})
		if !ok {
			t.Fatal("expected provider_types array in response")
		}

		// Should have at least Community providers (anthropic, openai, ollama)
		if len(types) < 3 {
			t.Errorf("expected at least 3 provider types, got %d", len(types))
		}
	})
}

// TestLLMProviderAPIHandler_RouteOrdering verifies that literal paths like /routing and /status
// are not captured by the {name} parameter. This is a regression test for route ordering in gorilla/mux.
func TestLLMProviderAPIHandler_RouteOrdering(t *testing.T) {
	registry := llm.NewRegistry()
	handler := NewLLMProviderAPIHandler(registry, nil)
	router := createTestRouter(handler)

	// Test that /routing is NOT treated as a provider name
	t.Run("/routing should hit routing endpoint not provider endpoint", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/routing", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should return 200 OK with routing config, NOT 404 for provider "routing"
		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d (route may be incorrectly captured by {name})", http.StatusOK, w.Code)
		}

		// Verify it's actually the routing response (has "weights" field)
		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if _, hasWeights := resp["weights"]; !hasWeights {
			t.Error("response should have 'weights' field for routing endpoint")
		}
	})

	// Test that /status is NOT treated as a provider name
	t.Run("/status should hit status endpoint not provider endpoint", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/status", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should return 200 OK with status, NOT 404 for provider "status"
		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d (route may be incorrectly captured by {name})", http.StatusOK, w.Code)
		}

		// Verify it's actually the status response (has "providers" field)
		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if _, hasProviders := resp["providers"]; !hasProviders {
			t.Error("response should have 'providers' field for status endpoint")
		}
	})

	// Test that actual provider names still work
	t.Run("actual provider name should hit provider endpoint", func(t *testing.T) {
		// Register a test provider
		config := &llm.ProviderConfig{
			Name:     "my-real-provider",
			TenantID: testProviderTenant,
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-key",
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), testProviderTenant, "my-real-provider")

		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/my-real-provider", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp LLMProviderResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Provider == nil || resp.Provider.Name != "my-real-provider" {
			t.Error("response should contain the provider 'my-real-provider'")
		}
	})
}

func TestLLMProviderAPIHandler_Routing(t *testing.T) {
	t.Run("returns empty routing config when no providers", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/routing", nil), testProviderTenant)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp LLMRoutingConfigResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(resp.Weights) != 0 {
			t.Errorf("expected empty weights, got %d", len(resp.Weights))
		}
	})

	t.Run("updates routing weights", func(t *testing.T) {
		registry := llm.NewRegistry()
		handler := NewLLMProviderAPIHandler(registry, nil)
		router := createTestRouter(handler)

		// Create provider first
		config := &llm.ProviderConfig{
			Name:     "routing-test-provider",
			TenantID: testProviderTenant,
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-key",
			Weight:   50,
		}
		registry.Register(context.Background(), config)
		defer registry.Unregister(context.Background(), testProviderTenant, "routing-test-provider")

		body := UpdateLLMRoutingRequest{
			Weights: map[string]int{
				"routing-test-provider": 100,
			},
		}
		bodyBytes, _ := json.Marshal(body)

		req := withTenant(httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/routing", bytes.NewReader(bodyBytes)), testProviderTenant)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp LLMRoutingConfigResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if weight, ok := resp.Weights["routing-test-provider"]; !ok || weight != 100 {
			t.Errorf("expected weight 100 for routing-test-provider, got %d", weight)
		}
	})
}
