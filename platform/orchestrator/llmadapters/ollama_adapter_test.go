//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Elastic License 2.0 (ELv2)
// Enterprise features - not available in Community distribution

package llmadapters

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"axonflow/platform/orchestrator/llm"
)

func TestOllamaAdapter_Name(t *testing.T) {
	tests := []struct {
		name     string
		adpName  string
		expected string
	}{
		{"default name", "", "ollama"},
		{"custom name", "ollama-local", "ollama-local"},
		{"another name", "local-llm", "local-llm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := NewOllamaAdapter(OllamaAdapterConfig{
				Name:     tt.adpName,
				Endpoint: "http://localhost:11434",
			})
			if err != nil {
				t.Fatalf("NewOllamaAdapter() error = %v", err)
			}

			if got := adapter.Name(); got != tt.expected {
				t.Errorf("Name() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOllamaAdapter_Type(t *testing.T) {
	adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
		Endpoint: "http://localhost:11434",
	})

	if got := adapter.Type(); got != llm.ProviderTypeOllama {
		t.Errorf("Type() = %v, want %v", got, llm.ProviderTypeOllama)
	}
}

func TestOllamaAdapter_Capabilities(t *testing.T) {
	adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
		Endpoint: "http://localhost:11434",
	})

	capabilities := adapter.Capabilities()

	expectedCaps := map[llm.Capability]bool{
		llm.CapabilityChat:       true,
		llm.CapabilityCompletion: true,
		llm.CapabilityStreaming:  true,
	}

	if len(capabilities) != len(expectedCaps) {
		t.Errorf("Capabilities() returned %d capabilities, want %d", len(capabilities), len(expectedCaps))
	}

	for _, cap := range capabilities {
		if !expectedCaps[cap] {
			t.Errorf("Unexpected capability: %v", cap)
		}
	}
}

func TestOllamaAdapter_SupportsStreaming(t *testing.T) {
	adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
		Endpoint: "http://localhost:11434",
	})

	if !adapter.SupportsStreaming() {
		t.Error("SupportsStreaming() = false, want true")
	}
}

func TestOllamaAdapter_Complete(t *testing.T) {
	t.Run("successful completion", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/generate" {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}
			if r.Method != http.MethodPost {
				t.Errorf("Unexpected method: %s", r.Method)
			}

			resp := ollamaResponse{
				Model:           "llama3",
				Response:        "Hello! How can I help you today?",
				Done:            true,
				PromptEvalCount: 10,
				EvalCount:       8,
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		adapter, err := NewOllamaAdapter(OllamaAdapterConfig{
			Name:     "test-ollama",
			Endpoint: server.URL,
			Model:    "llama3",
		})
		if err != nil {
			t.Fatalf("NewOllamaAdapter() error = %v", err)
		}

		req := llm.CompletionRequest{
			Prompt:      "Hello",
			MaxTokens:   100,
			Temperature: 0.7,
		}

		resp, err := adapter.Complete(context.Background(), req)

		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}

		if resp.Content != "Hello! How can I help you today?" {
			t.Errorf("Content = %v, want 'Hello! How can I help you today?'", resp.Content)
		}

		if resp.Model != "llama3" {
			t.Errorf("Model = %v, want 'llama3'", resp.Model)
		}

		if resp.Usage.PromptTokens != 10 {
			t.Errorf("PromptTokens = %v, want 10", resp.Usage.PromptTokens)
		}

		if resp.Usage.CompletionTokens != 8 {
			t.Errorf("CompletionTokens = %v, want 8", resp.Usage.CompletionTokens)
		}
	})

	t.Run("uses default model when not specified", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody ollamaRequest
			json.NewDecoder(r.Body).Decode(&reqBody)

			if reqBody.Model != "llama3" {
				t.Errorf("Request model = %v, want 'llama3'", reqBody.Model)
			}

			resp := ollamaResponse{
				Model:    "llama3",
				Response: "test",
				Done:     true,
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
			Endpoint: server.URL,
			Model:    "llama3",
		})

		req := llm.CompletionRequest{
			Prompt: "Hello",
		}

		_, err := adapter.Complete(context.Background(), req)
		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
	})

	t.Run("uses specified model when provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody ollamaRequest
			json.NewDecoder(r.Body).Decode(&reqBody)

			if reqBody.Model != "mistral" {
				t.Errorf("Request model = %v, want 'mistral'", reqBody.Model)
			}

			resp := ollamaResponse{
				Model:    "mistral",
				Response: "test",
				Done:     true,
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
			Endpoint: server.URL,
			Model:    "llama3",
		})

		req := llm.CompletionRequest{
			Prompt: "Hello",
			Model:  "mistral",
		}

		resp, err := adapter.Complete(context.Background(), req)
		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}

		if resp.Model != "mistral" {
			t.Errorf("Response model = %v, want 'mistral'", resp.Model)
		}
	})

	t.Run("error handling - server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal server error"))
		}))
		defer server.Close()

		adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
			Endpoint: server.URL,
		})

		req := llm.CompletionRequest{
			Prompt: "Hello",
		}

		_, err := adapter.Complete(context.Background(), req)

		if err == nil {
			t.Fatal("Complete() expected error, got nil")
		}

		providerErr, ok := err.(*llm.ProviderError)
		if !ok {
			t.Fatalf("expected *llm.ProviderError, got %T", err)
		}

		if providerErr.StatusCode != http.StatusInternalServerError {
			t.Errorf("StatusCode = %v, want %v", providerErr.StatusCode, http.StatusInternalServerError)
		}

		if !providerErr.Retryable {
			t.Error("Retryable = false, want true for 5xx errors")
		}
	})

	t.Run("error handling - connection refused", func(t *testing.T) {
		adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
			Endpoint: "http://localhost:99999", // Invalid port
		})

		req := llm.CompletionRequest{
			Prompt: "Hello",
		}

		_, err := adapter.Complete(context.Background(), req)

		if err == nil {
			t.Fatal("Complete() expected error, got nil")
		}

		providerErr, ok := err.(*llm.ProviderError)
		if !ok {
			t.Fatalf("expected *llm.ProviderError, got %T", err)
		}

		if providerErr.Code != llm.ErrCodeUnavailable {
			t.Errorf("Code = %v, want %v", providerErr.Code, llm.ErrCodeUnavailable)
		}
	})
}

func TestOllamaAdapter_HealthCheck(t *testing.T) {
	t.Run("healthy provider", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/tags" {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"models":[]}`))
		}))
		defer server.Close()

		adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
			Endpoint: server.URL,
		})

		result, err := adapter.HealthCheck(context.Background())

		if err != nil {
			t.Fatalf("HealthCheck() error = %v", err)
		}

		if result.Status != llm.HealthStatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, llm.HealthStatusHealthy)
		}

		if result.Latency <= 0 {
			t.Error("Latency should be > 0")
		}

		if result.LastChecked.IsZero() {
			t.Error("LastChecked should be set")
		}
	})

	t.Run("unhealthy provider - server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
			Endpoint: server.URL,
		})

		result, err := adapter.HealthCheck(context.Background())

		if err != nil {
			t.Fatalf("HealthCheck() error = %v", err)
		}

		if result.Status != llm.HealthStatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, llm.HealthStatusUnhealthy)
		}
	})

	t.Run("unhealthy provider - connection refused", func(t *testing.T) {
		adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
			Endpoint: "http://localhost:99999",
		})

		result, err := adapter.HealthCheck(context.Background())

		if err != nil {
			t.Fatalf("HealthCheck() error = %v", err)
		}

		if result.Status != llm.HealthStatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, llm.HealthStatusUnhealthy)
		}

		if result.Message == "" {
			t.Error("Message should contain error details")
		}
	})
}

func TestOllamaAdapter_EstimateCost(t *testing.T) {
	adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
		Endpoint: "http://localhost:11434",
	})

	tests := []struct {
		name       string
		prompt     string
		maxTokens  int
		wantInput  int
		wantOutput int
	}{
		{
			name:       "short prompt default tokens",
			prompt:     "Hello",
			maxTokens:  0,
			wantInput:  1,
			wantOutput: 1000,
		},
		{
			name:       "longer prompt with max tokens",
			prompt:     "This is a longer prompt with more characters",
			maxTokens:  500,
			wantInput:  11, // 44 chars / 4
			wantOutput: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := llm.CompletionRequest{
				Prompt:    tt.prompt,
				MaxTokens: tt.maxTokens,
			}

			estimate := adapter.EstimateCost(req)

			if estimate == nil {
				t.Fatal("EstimateCost() returned nil")
			}

			if estimate.EstimatedInputTokens != tt.wantInput {
				t.Errorf("EstimatedInputTokens = %v, want %v", estimate.EstimatedInputTokens, tt.wantInput)
			}

			if estimate.EstimatedOutputTokens != tt.wantOutput {
				t.Errorf("EstimatedOutputTokens = %v, want %v", estimate.EstimatedOutputTokens, tt.wantOutput)
			}

			if estimate.Currency != "USD" {
				t.Errorf("Currency = %v, want USD", estimate.Currency)
			}

			// Ollama is self-hosted - zero cost
			if estimate.InputCostPer1K != 0 {
				t.Errorf("InputCostPer1K = %v, want 0 for self-hosted Ollama", estimate.InputCostPer1K)
			}

			if estimate.OutputCostPer1K != 0 {
				t.Errorf("OutputCostPer1K = %v, want 0 for self-hosted Ollama", estimate.OutputCostPer1K)
			}

			if estimate.TotalEstimate != 0 {
				t.Errorf("TotalEstimate = %v, want 0 for self-hosted Ollama", estimate.TotalEstimate)
			}
		})
	}
}

func TestOllamaAdapter_CapabilitiesDoNotIncludeLongContext(t *testing.T) {
	adapter, _ := NewOllamaAdapter(OllamaAdapterConfig{
		Endpoint: "http://localhost:11434",
	})

	capabilities := adapter.Capabilities()

	for _, cap := range capabilities {
		if cap == llm.CapabilityLongContext {
			t.Error("Ollama should not include CapabilityLongContext by default")
		}
	}
}

func TestOllamaAdapterInterfaceCompliance(t *testing.T) {
	var _ llm.Provider = (*OllamaAdapter)(nil)
}

func TestNewOllamaAdapter_Defaults(t *testing.T) {
	adapter, err := NewOllamaAdapter(OllamaAdapterConfig{})
	if err != nil {
		t.Fatalf("NewOllamaAdapter() error = %v", err)
	}

	if adapter.endpoint != "http://localhost:11434" {
		t.Errorf("endpoint = %v, want 'http://localhost:11434'", adapter.endpoint)
	}

	if adapter.model != "llama3" {
		t.Errorf("model = %v, want 'llama3'", adapter.model)
	}

	if adapter.name != "ollama" {
		t.Errorf("name = %v, want 'ollama'", adapter.name)
	}
}
