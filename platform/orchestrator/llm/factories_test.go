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

package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axonflow/platform/orchestrator/llm/anthropic"
)

func TestAnthropicProviderFactory(t *testing.T) {
	t.Run("creates provider with valid config", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "anthropic-test",
			Type:   ProviderTypeAnthropic,
			APIKey: "test-api-key",
		}

		provider, err := NewAnthropicProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}

		if provider.Name() != "anthropic-test" {
			t.Errorf("expected name 'anthropic-test', got %q", provider.Name())
		}

		if provider.Type() != ProviderTypeAnthropic {
			t.Errorf("expected type %q, got %q", ProviderTypeAnthropic, provider.Type())
		}
	})

	t.Run("uses default model when not specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "anthropic-test",
			Type:   ProviderTypeAnthropic,
			APIKey: "test-api-key",
		}

		provider, err := NewAnthropicProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		// Check that it has capabilities (means it was created successfully with defaults)
		caps := provider.Capabilities()
		if len(caps) == 0 {
			t.Error("expected capabilities, got none")
		}
	})

	t.Run("uses custom model when specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "anthropic-test",
			Type:   ProviderTypeAnthropic,
			APIKey: "test-api-key",
			Model:  anthropic.ModelClaude3Opus,
		}

		provider, err := NewAnthropicProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}
	})

	t.Run("uses custom timeout when specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:           "anthropic-test",
			Type:           ProviderTypeAnthropic,
			APIKey:         "test-api-key",
			TimeoutSeconds: 60,
		}

		provider, err := NewAnthropicProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}
	})

	t.Run("uses custom endpoint when specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:     "anthropic-test",
			Type:     ProviderTypeAnthropic,
			APIKey:   "test-api-key",
			Endpoint: "https://custom-anthropic.example.com",
		}

		provider, err := NewAnthropicProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}
	})

	t.Run("returns error when API key is missing", func(t *testing.T) {
		config := ProviderConfig{
			Name: "anthropic-test",
			Type: ProviderTypeAnthropic,
		}

		_, err := NewAnthropicProviderFactory(config)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		factoryErr, ok := err.(*FactoryError)
		if !ok {
			t.Fatalf("expected FactoryError, got %T", err)
		}

		if factoryErr.Code != ErrFactoryInvalidConfig {
			t.Errorf("expected code %q, got %q", ErrFactoryInvalidConfig, factoryErr.Code)
		}
	})
}

func TestAnthropicProviderAdapter(t *testing.T) {
	t.Run("implements Provider interface correctly", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "anthropic-adapter-test",
			Type:   ProviderTypeAnthropic,
			APIKey: "test-api-key",
		}

		provider, err := NewAnthropicProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		// Check Name
		if provider.Name() != "anthropic-adapter-test" {
			t.Errorf("expected name 'anthropic-adapter-test', got %q", provider.Name())
		}

		// Check Type
		if provider.Type() != ProviderTypeAnthropic {
			t.Errorf("expected type %q, got %q", ProviderTypeAnthropic, provider.Type())
		}

		// Check Capabilities
		caps := provider.Capabilities()
		if len(caps) == 0 {
			t.Error("expected capabilities, got none")
		}

		// Check SupportsStreaming
		if !provider.SupportsStreaming() {
			t.Error("expected streaming support")
		}

		// Check EstimateCost
		estimate := provider.EstimateCost(CompletionRequest{
			Prompt:    "test prompt",
			MaxTokens: 100,
		})
		if estimate == nil {
			t.Error("expected cost estimate, got nil")
		}
		if estimate.Currency != "USD" {
			t.Errorf("expected currency USD, got %q", estimate.Currency)
		}
	})

	t.Run("HealthCheck returns status", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "anthropic-health-test",
			Type:   ProviderTypeAnthropic,
			APIKey: "test-api-key",
		}

		provider, err := NewAnthropicProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx := context.Background()
		result, err := provider.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if result == nil {
			t.Fatal("expected result, got nil")
		}

		// Should be healthy initially
		if result.Status != HealthStatusHealthy {
			t.Errorf("expected healthy status, got %q", result.Status)
		}
	})
}

func TestOpenAIProviderFactory(t *testing.T) {
	t.Run("creates provider with valid config", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "openai-test",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-api-key",
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}

		if provider.Name() != "openai-test" {
			t.Errorf("expected name 'openai-test', got %q", provider.Name())
		}

		if provider.Type() != ProviderTypeOpenAI {
			t.Errorf("expected type %q, got %q", ProviderTypeOpenAI, provider.Type())
		}
	})

	t.Run("uses default model when not specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "openai-test",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-api-key",
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		openai, ok := provider.(*OpenAIProvider)
		if !ok {
			t.Fatalf("expected *OpenAIProvider, got %T", provider)
		}

		if openai.model != OpenAIDefaultModel {
			t.Errorf("expected default model %q, got %q", OpenAIDefaultModel, openai.model)
		}
	})

	t.Run("uses custom model when specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "openai-test",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-api-key",
			Model:  "gpt-4-turbo",
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		openai, ok := provider.(*OpenAIProvider)
		if !ok {
			t.Fatalf("expected *OpenAIProvider, got %T", provider)
		}

		if openai.model != "gpt-4-turbo" {
			t.Errorf("expected model 'gpt-4-turbo', got %q", openai.model)
		}
	})

	t.Run("uses custom endpoint when specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:     "openai-test",
			Type:     ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: "https://custom-openai.example.com",
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		openai, ok := provider.(*OpenAIProvider)
		if !ok {
			t.Fatalf("expected *OpenAIProvider, got %T", provider)
		}

		if openai.endpoint != "https://custom-openai.example.com" {
			t.Errorf("expected custom endpoint, got %q", openai.endpoint)
		}
	})

	t.Run("returns error when API key is missing", func(t *testing.T) {
		config := ProviderConfig{
			Name: "openai-test",
			Type: ProviderTypeOpenAI,
		}

		_, err := NewOpenAIProviderFactory(config)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		factoryErr, ok := err.(*FactoryError)
		if !ok {
			t.Fatalf("expected FactoryError, got %T", err)
		}

		if factoryErr.Code != ErrFactoryInvalidConfig {
			t.Errorf("expected code %q, got %q", ErrFactoryInvalidConfig, factoryErr.Code)
		}
	})
}

func TestOpenAIProvider(t *testing.T) {
	t.Run("implements Provider interface correctly", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "openai-interface-test",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-api-key",
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		// Check Name
		if provider.Name() != "openai-interface-test" {
			t.Errorf("expected name 'openai-interface-test', got %q", provider.Name())
		}

		// Check Type
		if provider.Type() != ProviderTypeOpenAI {
			t.Errorf("expected type %q, got %q", ProviderTypeOpenAI, provider.Type())
		}

		// Check Capabilities
		caps := provider.Capabilities()
		if len(caps) == 0 {
			t.Error("expected capabilities, got none")
		}

		// Verify expected capabilities
		expectedCaps := []Capability{
			CapabilityChat,
			CapabilityCompletion,
			CapabilityStreaming,
		}
		for _, expected := range expectedCaps {
			found := false
			for _, cap := range caps {
				if cap == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected capability %q not found", expected)
			}
		}

		// Check SupportsStreaming
		if !provider.SupportsStreaming() {
			t.Error("expected streaming support")
		}
	})

	t.Run("Complete with mock server", func(t *testing.T) {
		// Create mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if !strings.HasSuffix(r.URL.Path, "/v1/chat/completions") {
				t.Errorf("expected path /v1/chat/completions, got %s", r.URL.Path)
			}

			// Check headers
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-api-key" {
				t.Errorf("expected auth header 'Bearer test-api-key', got %q", auth)
			}

			// Send response
			resp := map[string]any{
				"id":    "chatcmpl-123",
				"model": "gpt-4o",
				"choices": []map[string]any{
					{
						"index": 0,
						"message": map[string]string{
							"role":    "assistant",
							"content": "Hello! How can I help you?",
						},
						"finish_reason": "stop",
					},
				},
				"usage": map[string]int{
					"prompt_tokens":     10,
					"completion_tokens": 7,
					"total_tokens":      17,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode response: %v", err)
			}
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "openai-mock-test",
			Type:     ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: server.URL,
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx := context.Background()
		resp, err := provider.Complete(ctx, CompletionRequest{
			Prompt:    "Hello",
			MaxTokens: 100,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if resp.Content != "Hello! How can I help you?" {
			t.Errorf("expected content 'Hello! How can I help you?', got %q", resp.Content)
		}

		if resp.Model != "gpt-4o" {
			t.Errorf("expected model 'gpt-4o', got %q", resp.Model)
		}

		if resp.Usage.TotalTokens != 17 {
			t.Errorf("expected total tokens 17, got %d", resp.Usage.TotalTokens)
		}
	})

	t.Run("Complete handles API error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": {"message": "Invalid API key"}}`))
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "openai-error-test",
			Type:     ProviderTypeOpenAI,
			APIKey:   "invalid-key",
			Endpoint: server.URL,
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx := context.Background()
		_, err = provider.Complete(ctx, CompletionRequest{
			Prompt: "Hello",
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("HealthCheck returns status", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "openai-health-test",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-api-key",
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx := context.Background()
		result, err := provider.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if result == nil {
			t.Fatal("expected result, got nil")
		}

		// Should be healthy initially
		if result.Status != HealthStatusHealthy {
			t.Errorf("expected healthy status, got %q", result.Status)
		}
	})

	t.Run("EstimateCost returns valid estimate", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "openai-cost-test",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-api-key",
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		estimate := provider.EstimateCost(CompletionRequest{
			Prompt:    "This is a test prompt with some content",
			MaxTokens: 500,
		})

		if estimate == nil {
			t.Fatal("expected estimate, got nil")
		}

		if estimate.Currency != "USD" {
			t.Errorf("expected currency USD, got %q", estimate.Currency)
		}

		if estimate.InputCostPer1K <= 0 {
			t.Error("expected positive input cost")
		}

		if estimate.OutputCostPer1K <= 0 {
			t.Error("expected positive output cost")
		}

		if estimate.TotalEstimate <= 0 {
			t.Error("expected positive total estimate")
		}
	})
}

func TestOllamaProviderFactory(t *testing.T) {
	t.Run("creates provider with valid config", func(t *testing.T) {
		config := ProviderConfig{
			Name: "ollama-test",
			Type: ProviderTypeOllama,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}

		if provider.Name() != "ollama-test" {
			t.Errorf("expected name 'ollama-test', got %q", provider.Name())
		}

		if provider.Type() != ProviderTypeOllama {
			t.Errorf("expected type %q, got %q", ProviderTypeOllama, provider.Type())
		}
	})

	t.Run("does not require API key", func(t *testing.T) {
		config := ProviderConfig{
			Name: "ollama-no-key",
			Type: ProviderTypeOllama,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}
	})

	t.Run("uses default endpoint when not specified", func(t *testing.T) {
		config := ProviderConfig{
			Name: "ollama-test",
			Type: ProviderTypeOllama,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ollama, ok := provider.(*OllamaProvider)
		if !ok {
			t.Fatalf("expected *OllamaProvider, got %T", provider)
		}

		if ollama.endpoint != OllamaDefaultEndpoint {
			t.Errorf("expected default endpoint %q, got %q", OllamaDefaultEndpoint, ollama.endpoint)
		}
	})

	t.Run("uses custom endpoint when specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:     "ollama-test",
			Type:     ProviderTypeOllama,
			Endpoint: "http://custom-ollama:11434",
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ollama, ok := provider.(*OllamaProvider)
		if !ok {
			t.Fatalf("expected *OllamaProvider, got %T", provider)
		}

		if ollama.endpoint != "http://custom-ollama:11434" {
			t.Errorf("expected custom endpoint, got %q", ollama.endpoint)
		}
	})

	t.Run("normalizes endpoint by removing trailing slash", func(t *testing.T) {
		config := ProviderConfig{
			Name:     "ollama-test",
			Type:     ProviderTypeOllama,
			Endpoint: "http://ollama:11434/",
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ollama, ok := provider.(*OllamaProvider)
		if !ok {
			t.Fatalf("expected *OllamaProvider, got %T", provider)
		}

		if strings.HasSuffix(ollama.endpoint, "/") {
			t.Error("endpoint should not have trailing slash")
		}
	})

	t.Run("uses default model when not specified", func(t *testing.T) {
		config := ProviderConfig{
			Name: "ollama-test",
			Type: ProviderTypeOllama,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ollama, ok := provider.(*OllamaProvider)
		if !ok {
			t.Fatalf("expected *OllamaProvider, got %T", provider)
		}

		if ollama.model != OllamaDefaultModel {
			t.Errorf("expected default model %q, got %q", OllamaDefaultModel, ollama.model)
		}
	})

	t.Run("uses custom model when specified", func(t *testing.T) {
		config := ProviderConfig{
			Name:  "ollama-test",
			Type:  ProviderTypeOllama,
			Model: "mistral:7b",
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ollama, ok := provider.(*OllamaProvider)
		if !ok {
			t.Fatalf("expected *OllamaProvider, got %T", provider)
		}

		if ollama.model != "mistral:7b" {
			t.Errorf("expected model 'mistral:7b', got %q", ollama.model)
		}
	})
}

func TestOllamaProvider(t *testing.T) {
	t.Run("implements Provider interface correctly", func(t *testing.T) {
		config := ProviderConfig{
			Name: "ollama-interface-test",
			Type: ProviderTypeOllama,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		// Check Name
		if provider.Name() != "ollama-interface-test" {
			t.Errorf("expected name 'ollama-interface-test', got %q", provider.Name())
		}

		// Check Type
		if provider.Type() != ProviderTypeOllama {
			t.Errorf("expected type %q, got %q", ProviderTypeOllama, provider.Type())
		}

		// Check Capabilities
		caps := provider.Capabilities()
		if len(caps) == 0 {
			t.Error("expected capabilities, got none")
		}

		// Check SupportsStreaming
		if !provider.SupportsStreaming() {
			t.Error("expected streaming support")
		}
	})

	t.Run("Complete with mock server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if !strings.HasSuffix(r.URL.Path, "/api/generate") {
				t.Errorf("expected path /api/generate, got %s", r.URL.Path)
			}

			// Parse request body
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request: %v", err)
			}

			// Verify stream is false
			if stream, ok := req["stream"].(bool); !ok || stream {
				t.Error("expected stream: false")
			}

			// Send response
			resp := map[string]any{
				"model":               "llama3.1:latest",
				"response":            "Hello! I'm Ollama.",
				"done":                true,
				"total_duration":      1000000000,
				"load_duration":       100000000,
				"prompt_eval_count":   5,
				"prompt_eval_duration": 200000000,
				"eval_count":          4,
				"eval_duration":       700000000,
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode response: %v", err)
			}
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "ollama-mock-test",
			Type:     ProviderTypeOllama,
			Endpoint: server.URL,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx := context.Background()
		resp, err := provider.Complete(ctx, CompletionRequest{
			Prompt:    "Hello",
			MaxTokens: 100,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if resp.Content != "Hello! I'm Ollama." {
			t.Errorf("expected content 'Hello! I'm Ollama.', got %q", resp.Content)
		}

		if resp.Model != "llama3.1:latest" {
			t.Errorf("expected model 'llama3.1:latest', got %q", resp.Model)
		}

		if resp.Usage.PromptTokens != 5 {
			t.Errorf("expected prompt tokens 5, got %d", resp.Usage.PromptTokens)
		}

		if resp.Usage.CompletionTokens != 4 {
			t.Errorf("expected completion tokens 4, got %d", resp.Usage.CompletionTokens)
		}
	})

	t.Run("Complete handles API error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "model not found"}`))
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "ollama-error-test",
			Type:     ProviderTypeOllama,
			Endpoint: server.URL,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx := context.Background()
		_, err = provider.Complete(ctx, CompletionRequest{
			Prompt: "Hello",
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("HealthCheck with healthy server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/tags" {
				resp := map[string]any{
					"models": []map[string]any{
						{"name": "llama3.1:latest"},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "ollama-health-test",
			Type:     ProviderTypeOllama,
			Endpoint: server.URL,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx := context.Background()
		result, err := provider.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if result.Status != HealthStatusHealthy {
			t.Errorf("expected healthy status, got %q", result.Status)
		}
	})

	t.Run("HealthCheck with unhealthy server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "ollama-unhealthy-test",
			Type:     ProviderTypeOllama,
			Endpoint: server.URL,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx := context.Background()
		result, err := provider.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if result.Status != HealthStatusUnhealthy {
			t.Errorf("expected unhealthy status, got %q", result.Status)
		}
	})

	t.Run("HealthCheck with connection error", func(t *testing.T) {
		config := ProviderConfig{
			Name:     "ollama-connection-error-test",
			Type:     ProviderTypeOllama,
			Endpoint: "http://localhost:99999", // Invalid port
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		result, err := provider.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if result.Status != HealthStatusUnhealthy {
			t.Errorf("expected unhealthy status, got %q", result.Status)
		}
	})

	t.Run("EstimateCost returns zero cost for self-hosted", func(t *testing.T) {
		config := ProviderConfig{
			Name: "ollama-cost-test",
			Type: ProviderTypeOllama,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		estimate := provider.EstimateCost(CompletionRequest{
			Prompt:    "This is a test prompt",
			MaxTokens: 500,
		})

		if estimate == nil {
			t.Fatal("expected estimate, got nil")
		}

		if estimate.InputCostPer1K != 0 {
			t.Errorf("expected zero input cost, got %f", estimate.InputCostPer1K)
		}

		if estimate.OutputCostPer1K != 0 {
			t.Errorf("expected zero output cost, got %f", estimate.OutputCostPer1K)
		}

		if estimate.TotalEstimate != 0 {
			t.Errorf("expected zero total estimate, got %f", estimate.TotalEstimate)
		}
	})
}

func TestOpenAIProvider_CompleteStream(t *testing.T) {
	t.Run("streams response correctly", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify streaming header
			if r.Header.Get("Accept") != "text/event-stream" {
				t.Errorf("expected Accept: text/event-stream, got %q", r.Header.Get("Accept"))
			}

			// Send SSE response
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			// Write chunks
			chunks := []string{
				`data: {"id":"1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`,
				`data: {"id":"1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":" World"},"finish_reason":null}]}`,
				`data: {"id":"1","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
				`data: [DONE]`,
			}
			for _, chunk := range chunks {
				w.Write([]byte(chunk + "\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "openai-stream-test",
			Type:     ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: server.URL,
		}

		provider, err := NewOpenAIProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		streamProvider, ok := provider.(StreamingProvider)
		if !ok {
			t.Fatal("expected provider to implement StreamingProvider")
		}

		var receivedChunks []string
		handler := func(chunk StreamChunk) error {
			if chunk.Content != "" {
				receivedChunks = append(receivedChunks, chunk.Content)
			}
			return nil
		}

		ctx := context.Background()
		resp, err := streamProvider.CompleteStream(ctx, CompletionRequest{
			Prompt:    "Hi",
			MaxTokens: 100,
		}, handler)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if resp.Content != "Hello World" {
			t.Errorf("expected content 'Hello World', got %q", resp.Content)
		}

		if len(receivedChunks) != 2 {
			t.Errorf("expected 2 chunks, got %d", len(receivedChunks))
		}
	})

	t.Run("handles handler error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`data: {"id":"1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Test"},"finish_reason":null}]}` + "\n\n"))
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "openai-stream-error-test",
			Type:     ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: server.URL,
		}

		provider, _ := NewOpenAIProviderFactory(config)
		streamProvider := provider.(StreamingProvider)

		handlerErr := fmt.Errorf("handler error")
		handler := func(_ StreamChunk) error {
			return handlerErr
		}

		_, err := streamProvider.CompleteStream(context.Background(), CompletionRequest{Prompt: "Hi"}, handler)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "handler error") {
			t.Errorf("expected handler error, got: %v", err)
		}
	})
}

func TestOllamaProvider_CompleteStream(t *testing.T) {
	t.Run("streams response correctly", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request has stream: true
			var req map[string]any
			json.NewDecoder(r.Body).Decode(&req)
			if stream, ok := req["stream"].(bool); !ok || !stream {
				t.Error("expected stream: true")
			}

			// Send NDJSON response
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)

			chunks := []string{
				`{"model":"llama3.1","response":"Hello","done":false}`,
				`{"model":"llama3.1","response":" World","done":false}`,
				`{"model":"llama3.1","response":"","done":true,"prompt_eval_count":5,"eval_count":2}`,
			}
			for _, chunk := range chunks {
				w.Write([]byte(chunk + "\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}))
		defer server.Close()

		config := ProviderConfig{
			Name:     "ollama-stream-test",
			Type:     ProviderTypeOllama,
			Endpoint: server.URL,
		}

		provider, err := NewOllamaProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		streamProvider, ok := provider.(StreamingProvider)
		if !ok {
			t.Fatal("expected provider to implement StreamingProvider")
		}

		var receivedChunks []string
		handler := func(chunk StreamChunk) error {
			if chunk.Content != "" {
				receivedChunks = append(receivedChunks, chunk.Content)
			}
			return nil
		}

		ctx := context.Background()
		resp, err := streamProvider.CompleteStream(ctx, CompletionRequest{
			Prompt:    "Hi",
			MaxTokens: 100,
		}, handler)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if resp.Content != "Hello World" {
			t.Errorf("expected content 'Hello World', got %q", resp.Content)
		}

		if len(receivedChunks) != 2 {
			t.Errorf("expected 2 chunks, got %d", len(receivedChunks))
		}

		if resp.Usage.PromptTokens != 5 {
			t.Errorf("expected 5 prompt tokens, got %d", resp.Usage.PromptTokens)
		}
	})
}

func TestFactoriesRegistration(t *testing.T) {
	t.Run("Anthropic factory is registered", func(t *testing.T) {
		if !HasFactory(ProviderTypeAnthropic) {
			t.Error("expected Anthropic factory to be registered")
		}
	})

	t.Run("OpenAI factory is registered", func(t *testing.T) {
		if !HasFactory(ProviderTypeOpenAI) {
			t.Error("expected OpenAI factory to be registered")
		}
	})

	t.Run("Ollama factory is registered", func(t *testing.T) {
		if !HasFactory(ProviderTypeOllama) {
			t.Error("expected Ollama factory to be registered")
		}
	})

	t.Run("can create Anthropic provider via CreateProvider", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "anthropic-via-create",
			Type:   ProviderTypeAnthropic,
			APIKey: "test-key",
		}

		provider, err := CreateProvider(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}

		if provider.Type() != ProviderTypeAnthropic {
			t.Errorf("expected type %q, got %q", ProviderTypeAnthropic, provider.Type())
		}
	})

	t.Run("can create OpenAI provider via CreateProvider", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "openai-via-create",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-key",
		}

		provider, err := CreateProvider(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}

		if provider.Type() != ProviderTypeOpenAI {
			t.Errorf("expected type %q, got %q", ProviderTypeOpenAI, provider.Type())
		}
	})

	t.Run("can create Ollama provider via CreateProvider", func(t *testing.T) {
		config := ProviderConfig{
			Name: "ollama-via-create",
			Type: ProviderTypeOllama,
		}

		provider, err := CreateProvider(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}

		if provider.Type() != ProviderTypeOllama {
			t.Errorf("expected type %q, got %q", ProviderTypeOllama, provider.Type())
		}
	})
}
