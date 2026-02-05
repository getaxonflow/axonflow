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

package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/orchestrator/llm"
)

func TestProviderFactory(t *testing.T) {
	t.Run("creates provider with valid config", func(t *testing.T) {
		config := llm.ProviderConfig{
			Name:   "openai-test",
			Type:   llm.ProviderTypeOpenAI,
			APIKey: "test-api-key",
		}

		provider, err := NewProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider == nil {
			t.Fatal("expected provider, got nil")
		}

		if provider.Name() != "openai-test" {
			t.Errorf("expected name 'openai-test', got %q", provider.Name())
		}

		if provider.Type() != llm.ProviderTypeOpenAI {
			t.Errorf("expected type %q, got %q", llm.ProviderTypeOpenAI, provider.Type())
		}
	})

	t.Run("uses default model when not specified", func(t *testing.T) {
		config := llm.ProviderConfig{
			Name:   "openai-test",
			Type:   llm.ProviderTypeOpenAI,
			APIKey: "test-api-key",
		}

		provider, err := NewProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		openaiProvider, ok := provider.(*Provider)
		if !ok {
			t.Fatalf("expected *Provider, got %T", provider)
		}

		if openaiProvider.Model() != llm.OpenAIDefaultModel {
			t.Errorf("expected default model %q, got %q", llm.OpenAIDefaultModel, openaiProvider.Model())
		}
	})

	t.Run("uses custom model when specified", func(t *testing.T) {
		config := llm.ProviderConfig{
			Name:   "openai-test",
			Type:   llm.ProviderTypeOpenAI,
			APIKey: "test-api-key",
			Model:  "gpt-4-turbo",
		}

		provider, err := NewProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		openaiProvider, ok := provider.(*Provider)
		if !ok {
			t.Fatalf("expected *Provider, got %T", provider)
		}

		if openaiProvider.Model() != "gpt-4-turbo" {
			t.Errorf("expected model 'gpt-4-turbo', got %q", openaiProvider.Model())
		}
	})

	t.Run("uses custom endpoint when specified", func(t *testing.T) {
		config := llm.ProviderConfig{
			Name:     "openai-test",
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: "https://custom-openai.example.com",
		}

		provider, err := NewProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		openaiProvider, ok := provider.(*Provider)
		if !ok {
			t.Fatalf("expected *Provider, got %T", provider)
		}

		if openaiProvider.Endpoint() != "https://custom-openai.example.com" {
			t.Errorf("expected custom endpoint, got %q", openaiProvider.Endpoint())
		}
	})

	t.Run("returns error when API key is missing", func(t *testing.T) {
		config := llm.ProviderConfig{
			Name: "openai-test",
			Type: llm.ProviderTypeOpenAI,
		}

		_, err := NewProviderFactory(config)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		factoryErr, ok := err.(*llm.FactoryError)
		if !ok {
			t.Fatalf("expected FactoryError, got %T", err)
		}

		if factoryErr.Code != llm.ErrFactoryInvalidConfig {
			t.Errorf("expected code %q, got %q", llm.ErrFactoryInvalidConfig, factoryErr.Code)
		}
	})
}

func TestFactoryRegistration(t *testing.T) {
	if !llm.HasFactory(llm.ProviderTypeOpenAI) {
		t.Fatal("expected OpenAI factory to be registered")
	}

	provider, err := llm.CreateProvider(llm.ProviderConfig{
		Name:   "openai-via-create",
		Type:   llm.ProviderTypeOpenAI,
		APIKey: "test-key",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if provider == nil {
		t.Fatal("expected provider, got nil")
	}

	if provider.Type() != llm.ProviderTypeOpenAI {
		t.Errorf("expected type %q, got %q", llm.ProviderTypeOpenAI, provider.Type())
	}
}

func TestProviderBehavior(t *testing.T) {
	t.Run("implements Provider interface correctly", func(t *testing.T) {
		config := llm.ProviderConfig{
			Name:   "openai-interface-test",
			Type:   llm.ProviderTypeOpenAI,
			APIKey: "test-api-key",
		}

		provider, err := NewProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if provider.Name() != "openai-interface-test" {
			t.Errorf("expected name 'openai-interface-test', got %q", provider.Name())
		}

		if provider.Type() != llm.ProviderTypeOpenAI {
			t.Errorf("expected type %q, got %q", llm.ProviderTypeOpenAI, provider.Type())
		}

		caps := provider.Capabilities()
		if len(caps) == 0 {
			t.Error("expected capabilities, got none")
		}

		if !provider.SupportsStreaming() {
			t.Error("expected streaming support")
		}
	})

	t.Run("Complete with mock server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if !strings.HasSuffix(r.URL.Path, "/v1/chat/completions") {
				t.Errorf("expected path /v1/chat/completions, got %s", r.URL.Path)
			}

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-api-key" {
				t.Errorf("expected auth header 'Bearer test-api-key', got %q", auth)
			}

			resp := map[string]any{
				"id":    "chatcmpl-123",
				"model": "gpt-4o",
				"choices": []map[string]any{
					{
						"index": 0,
						"message": map[string]string{
							"role":    "assistant",
							"content": "Hello, world!",
						},
						"finish_reason": "stop",
					},
				},
				"usage": map[string]int{
					"prompt_tokens":     5,
					"completion_tokens": 3,
					"total_tokens":      8,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := llm.ProviderConfig{
			Name:     "openai-complete-test",
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: server.URL,
		}

		provider, err := NewProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		resp, err := provider.Complete(context.Background(), llm.CompletionRequest{
			Prompt:    "Hello",
			MaxTokens: 100,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if resp.Content != "Hello, world!" {
			t.Errorf("expected content 'Hello, world!', got %q", resp.Content)
		}
	})

	t.Run("Complete returns error on API error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
		}))
		defer server.Close()

		config := llm.ProviderConfig{
			Name:     "openai-error-test",
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: server.URL,
		}

		provider, err := NewProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		_, err = provider.Complete(context.Background(), llm.CompletionRequest{Prompt: "Hi"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestProviderCompleteStream(t *testing.T) {
	t.Run("streams response correctly", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept") != "text/event-stream" {
				t.Errorf("expected Accept: text/event-stream, got %q", r.Header.Get("Accept"))
			}

			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

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

		config := llm.ProviderConfig{
			Name:     "openai-stream-test",
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: server.URL,
		}

		provider, err := NewProviderFactory(config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		streamProvider, ok := provider.(llm.StreamingProvider)
		if !ok {
			t.Fatal("expected provider to implement StreamingProvider")
		}

		var receivedChunks []string
		handler := func(chunk llm.StreamChunk) error {
			if chunk.Content != "" {
				receivedChunks = append(receivedChunks, chunk.Content)
			}
			return nil
		}

		resp, err := streamProvider.CompleteStream(context.Background(), llm.CompletionRequest{
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

		config := llm.ProviderConfig{
			Name:     "openai-stream-error-test",
			Type:     llm.ProviderTypeOpenAI,
			APIKey:   "test-api-key",
			Endpoint: server.URL,
		}

		provider, _ := NewProviderFactory(config)
		streamProvider := provider.(llm.StreamingProvider)

		handlerErr := fmt.Errorf("handler error")
		handler := func(_ llm.StreamChunk) error {
			return handlerErr
		}

		_, err := streamProvider.CompleteStream(context.Background(), llm.CompletionRequest{Prompt: "Hi"}, handler)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "handler error") {
			t.Errorf("expected handler error, got: %v", err)
		}
	})
}

func TestProviderEstimateCost(t *testing.T) {
	provider, err := NewProvider(Config{
		Name:   "openai-cost-test",
		APIKey: "test-api-key",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	estimate := provider.EstimateCost(llm.CompletionRequest{
		Prompt:    "This is a test prompt",
		MaxTokens: 500,
	})

	if estimate == nil {
		t.Fatal("expected estimate, got nil")
	}

	if estimate.TotalEstimate <= 0 {
		t.Errorf("expected positive cost estimate, got %f", estimate.TotalEstimate)
	}
}

func TestProviderHealthCheck(t *testing.T) {
	provider, err := NewProvider(Config{
		Name:   "openai-health-test",
		APIKey: "test-api-key",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result, err := provider.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.Status != llm.HealthStatusHealthy {
		t.Errorf("expected healthy status, got %q", result.Status)
	}
}
