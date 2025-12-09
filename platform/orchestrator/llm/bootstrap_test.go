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

package llm

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// testEnvHelper provides helpers for managing environment variables in tests.
type testEnvHelper struct {
	t        *testing.T
	original map[string]string
}

func newTestEnvHelper(t *testing.T) *testEnvHelper {
	return &testEnvHelper{
		t:        t,
		original: make(map[string]string),
	}
}

func (h *testEnvHelper) Set(key, value string) {
	if _, exists := h.original[key]; !exists {
		h.original[key] = os.Getenv(key)
	}
	if err := os.Setenv(key, value); err != nil {
		h.t.Fatalf("failed to set env var %s: %v", key, err)
	}
}

func (h *testEnvHelper) Unset(key string) {
	if _, exists := h.original[key]; !exists {
		h.original[key] = os.Getenv(key)
	}
	if err := os.Unsetenv(key); err != nil {
		h.t.Fatalf("failed to unset env var %s: %v", key, err)
	}
}

func (h *testEnvHelper) Restore() {
	for key, value := range h.original {
		if value == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, value)
		}
	}
}

func TestBootstrapFromEnv(t *testing.T) {
	t.Run("bootstraps Anthropic from env", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Clear other providers
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)

		// Set Anthropic config
		env.Set(EnvAnthropicAPIKey, "test-anthropic-key")
		env.Set(EnvAnthropicModel, "claude-3-5-sonnet-20241022")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 1 {
			t.Errorf("expected 1 provider, got %d", len(result.ProvidersBootstrapped))
		}

		if !contains(result.ProvidersBootstrapped, "anthropic") {
			t.Error("expected anthropic in bootstrapped providers")
		}

		if !result.Registry.Has("anthropic") {
			t.Error("expected anthropic to be registered")
		}
	})

	t.Run("bootstraps OpenAI from env", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Clear other providers
		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)

		// Set OpenAI config
		env.Set(EnvOpenAIAPIKey, "test-openai-key")
		env.Set(EnvOpenAIModel, "gpt-4o")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 1 {
			t.Errorf("expected 1 provider, got %d", len(result.ProvidersBootstrapped))
		}

		if !contains(result.ProvidersBootstrapped, "openai") {
			t.Error("expected openai in bootstrapped providers")
		}
	})

	t.Run("bootstraps Ollama from env", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Clear other providers
		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvBedrockRegion)

		// Set Ollama config
		env.Set(EnvOllamaEndpoint, "http://localhost:11434")
		env.Set(EnvOllamaModel, "llama3.1:latest")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 1 {
			t.Errorf("expected 1 provider, got %d", len(result.ProvidersBootstrapped))
		}

		if !contains(result.ProvidersBootstrapped, "ollama") {
			t.Error("expected ollama in bootstrapped providers")
		}
	})

	t.Run("bootstraps multiple providers", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Clear other providers
		env.Unset(EnvBedrockRegion)

		// Set all OSS providers
		env.Set(EnvAnthropicAPIKey, "test-anthropic-key")
		env.Set(EnvOpenAIAPIKey, "test-openai-key")
		env.Set(EnvOllamaEndpoint, "http://localhost:11434")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 3 {
			t.Errorf("expected 3 providers, got %d", len(result.ProvidersBootstrapped))
		}

		if !contains(result.ProvidersBootstrapped, "anthropic") {
			t.Error("expected anthropic in bootstrapped providers")
		}
		if !contains(result.ProvidersBootstrapped, "openai") {
			t.Error("expected openai in bootstrapped providers")
		}
		if !contains(result.ProvidersBootstrapped, "ollama") {
			t.Error("expected ollama in bootstrapped providers")
		}
	})

	t.Run("handles no providers configured", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Clear all providers
		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 0 {
			t.Errorf("expected 0 providers, got %d", len(result.ProvidersBootstrapped))
		}
	})

	t.Run("respects enabled providers filter", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Set all OSS providers
		env.Set(EnvAnthropicAPIKey, "test-anthropic-key")
		env.Set(EnvOpenAIAPIKey, "test-openai-key")
		env.Set(EnvOllamaEndpoint, "http://localhost:11434")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck:  true,
			EnabledProviders: []ProviderType{ProviderTypeAnthropic},
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 1 {
			t.Errorf("expected 1 provider, got %d", len(result.ProvidersBootstrapped))
		}

		if !contains(result.ProvidersBootstrapped, "anthropic") {
			t.Error("expected anthropic in bootstrapped providers")
		}

		if contains(result.ProvidersBootstrapped, "openai") {
			t.Error("expected openai to be filtered out")
		}
	})

	t.Run("respects LLM_PROVIDERS env filter", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Set all OSS providers
		env.Set(EnvAnthropicAPIKey, "test-anthropic-key")
		env.Set(EnvOpenAIAPIKey, "test-openai-key")
		env.Set(EnvOllamaEndpoint, "http://localhost:11434")
		env.Set(EnvLLMProviders, "openai,ollama")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 2 {
			t.Errorf("expected 2 providers, got %d", len(result.ProvidersBootstrapped))
		}

		if contains(result.ProvidersBootstrapped, "anthropic") {
			t.Error("expected anthropic to be filtered out")
		}
	})

	t.Run("sets default provider from env", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvBedrockRegion)
		env.Unset(EnvOllamaEndpoint)
		env.Set(EnvAnthropicAPIKey, "test-anthropic-key")
		env.Set(EnvOpenAIAPIKey, "test-openai-key")
		env.Set(EnvLLMDefaultProvider, "openai")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if result.DefaultProvider != "openai" {
			t.Errorf("expected default provider 'openai', got %q", result.DefaultProvider)
		}
	})

	t.Run("warns when default provider not available", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvBedrockRegion)
		env.Unset(EnvOllamaEndpoint)
		env.Set(EnvAnthropicAPIKey, "test-anthropic-key")
		env.Set(EnvLLMDefaultProvider, "nonexistent")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if result.DefaultProvider != "" {
			t.Errorf("expected empty default provider, got %q", result.DefaultProvider)
		}

		hasWarning := false
		for _, w := range result.Warnings {
			if strings.Contains(w, "nonexistent") {
				hasWarning = true
				break
			}
		}
		if !hasWarning {
			t.Error("expected warning about nonexistent default provider")
		}
	})

	t.Run("uses custom logger", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)

		var buf strings.Builder
		logger := log.New(&buf, "[TEST] ", 0)

		_, err := BootstrapFromEnv(&BootstrapConfig{
			Logger:          logger,
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if !strings.Contains(buf.String(), "Bootstrap complete") {
			t.Error("expected bootstrap message in log")
		}
	})

	t.Run("uses custom registry", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvBedrockRegion)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvOpenAIAPIKey)
		env.Set(EnvAnthropicAPIKey, "test-key")

		registry := NewRegistry()

		result, err := BootstrapFromEnv(&BootstrapConfig{
			Registry:        registry,
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		// Verify the same registry was used
		if result.Registry != registry {
			t.Error("expected same registry to be returned")
		}

		if !registry.Has("anthropic") {
			t.Error("expected anthropic to be registered in provided registry")
		}
	})

	t.Run("applies default weights", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvBedrockRegion)
		env.Unset(EnvOllamaEndpoint)
		env.Set(EnvAnthropicAPIKey, "test-key")
		env.Set(EnvOpenAIAPIKey, "test-key")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
			DefaultWeights: map[ProviderType]float64{
				ProviderTypeAnthropic: 0.7,
				ProviderTypeOpenAI:    0.3,
			},
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 2 {
			t.Errorf("expected 2 providers, got %d", len(result.ProvidersBootstrapped))
		}
	})

	t.Run("uses custom timeout settings", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)
		env.Set(EnvAnthropicAPIKey, "test-key")
		env.Set(EnvAnthropicTimeout, "60")

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck: true,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 1 {
			t.Errorf("expected 1 provider, got %d", len(result.ProvidersBootstrapped))
		}
	})
}

func TestBootstrapHealthCheck(t *testing.T) {
	t.Run("performs health check when not skipped", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Create mock Ollama server that responds to health check
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/tags" {
				resp := map[string]any{"models": []any{}}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvBedrockRegion)
		env.Set(EnvOllamaEndpoint, server.URL)

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck:    false,
			HealthCheckTimeout: 5 * time.Second,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(result.ProvidersBootstrapped) != 1 {
			t.Errorf("expected 1 provider, got %d", len(result.ProvidersBootstrapped))
		}
	})

	t.Run("records warning for unhealthy provider", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Create mock server that returns unhealthy status
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvBedrockRegion)
		env.Set(EnvOllamaEndpoint, server.URL)

		result, err := BootstrapFromEnv(&BootstrapConfig{
			SkipHealthCheck:    false,
			HealthCheckTimeout: 2 * time.Second,
		})

		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		// Provider should still be bootstrapped
		if len(result.ProvidersBootstrapped) != 1 {
			t.Errorf("expected 1 provider, got %d", len(result.ProvidersBootstrapped))
		}

		// But should have a warning
		hasWarning := false
		for _, w := range result.Warnings {
			if strings.Contains(w, "ollama") && strings.Contains(w, "health") {
				hasWarning = true
				break
			}
		}
		if !hasWarning {
			t.Error("expected health warning for unhealthy provider")
		}
	})
}

func TestDetectConfiguredProviders(t *testing.T) {
	t.Run("detects Anthropic", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)
		env.Set(EnvAnthropicAPIKey, "test-key")

		configured := DetectConfiguredProviders()

		if len(configured) != 1 {
			t.Errorf("expected 1 configured provider, got %d", len(configured))
		}

		if !containsProviderType(configured, ProviderTypeAnthropic) {
			t.Error("expected Anthropic to be detected")
		}
	})

	t.Run("detects OpenAI", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)
		env.Set(EnvOpenAIAPIKey, "test-key")

		configured := DetectConfiguredProviders()

		if !containsProviderType(configured, ProviderTypeOpenAI) {
			t.Error("expected OpenAI to be detected")
		}
	})

	t.Run("detects Ollama", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvBedrockRegion)
		env.Set(EnvOllamaEndpoint, "http://localhost:11434")

		configured := DetectConfiguredProviders()

		if !containsProviderType(configured, ProviderTypeOllama) {
			t.Error("expected Ollama to be detected")
		}
	})

	t.Run("detects Bedrock", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Set(EnvBedrockRegion, "us-east-1")

		configured := DetectConfiguredProviders()

		if !containsProviderType(configured, ProviderTypeBedrock) {
			t.Error("expected Bedrock to be detected")
		}
	})

	t.Run("detects multiple providers", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Set(EnvAnthropicAPIKey, "test-key")
		env.Set(EnvOpenAIAPIKey, "test-key")
		env.Set(EnvOllamaEndpoint, "http://localhost:11434")
		env.Set(EnvBedrockRegion, "us-east-1")

		configured := DetectConfiguredProviders()

		if len(configured) != 4 {
			t.Errorf("expected 4 configured providers, got %d", len(configured))
		}
	})

	t.Run("returns empty when none configured", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)

		configured := DetectConfiguredProviders()

		if len(configured) != 0 {
			t.Errorf("expected 0 configured providers, got %d", len(configured))
		}
	})
}

func TestGetProviderEnvVars(t *testing.T) {
	t.Run("returns Anthropic env vars", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Set(EnvAnthropicAPIKey, "sk-ant-test12345678")
		env.Set(EnvAnthropicModel, "claude-3-5-sonnet")
		env.Set(EnvAnthropicEndpoint, "https://custom.anthropic.com")
		env.Set(EnvAnthropicTimeout, "120")

		vars := GetProviderEnvVars(ProviderTypeAnthropic)

		// API key should be masked
		if !strings.Contains(vars[EnvAnthropicAPIKey], "...") {
			t.Error("expected API key to be masked")
		}

		if vars[EnvAnthropicModel] != "claude-3-5-sonnet" {
			t.Errorf("expected model value, got %q", vars[EnvAnthropicModel])
		}

		if vars[EnvAnthropicEndpoint] != "https://custom.anthropic.com" {
			t.Errorf("expected endpoint value, got %q", vars[EnvAnthropicEndpoint])
		}

		if vars[EnvAnthropicTimeout] != "120" {
			t.Errorf("expected timeout value, got %q", vars[EnvAnthropicTimeout])
		}
	})

	t.Run("returns OpenAI env vars", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Set(EnvOpenAIAPIKey, "sk-test12345678")
		env.Set(EnvOpenAIModel, "gpt-4o")

		vars := GetProviderEnvVars(ProviderTypeOpenAI)

		if !strings.Contains(vars[EnvOpenAIAPIKey], "...") {
			t.Error("expected API key to be masked")
		}

		if vars[EnvOpenAIModel] != "gpt-4o" {
			t.Errorf("expected model value, got %q", vars[EnvOpenAIModel])
		}
	})

	t.Run("returns Ollama env vars", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Set(EnvOllamaEndpoint, "http://localhost:11434")
		env.Set(EnvOllamaModel, "llama3.1:latest")

		vars := GetProviderEnvVars(ProviderTypeOllama)

		if vars[EnvOllamaEndpoint] != "http://localhost:11434" {
			t.Errorf("expected endpoint value, got %q", vars[EnvOllamaEndpoint])
		}

		if vars[EnvOllamaModel] != "llama3.1:latest" {
			t.Errorf("expected model value, got %q", vars[EnvOllamaModel])
		}
	})

	t.Run("returns Bedrock env vars", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Set(EnvBedrockRegion, "us-east-1")
		env.Set(EnvBedrockModel, "anthropic.claude-3-5-sonnet")

		vars := GetProviderEnvVars(ProviderTypeBedrock)

		if vars[EnvBedrockRegion] != "us-east-1" {
			t.Errorf("expected region value, got %q", vars[EnvBedrockRegion])
		}

		if vars[EnvBedrockModel] != "anthropic.claude-3-5-sonnet" {
			t.Errorf("expected model value, got %q", vars[EnvBedrockModel])
		}
	})
}

func TestValidateEnvironment(t *testing.T) {
	t.Run("returns error when no providers configured", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)

		errors := ValidateEnvironment()

		if len(errors) == 0 {
			t.Error("expected validation error")
		}

		hasProviderError := false
		for _, e := range errors {
			if strings.Contains(e, "No LLM providers configured") {
				hasProviderError = true
				break
			}
		}
		if !hasProviderError {
			t.Error("expected error about no providers configured")
		}
	})

	t.Run("returns no error when provider configured", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Set(EnvAnthropicAPIKey, "test-key")
		env.Unset(EnvOllamaModel)

		errors := ValidateEnvironment()

		for _, e := range errors {
			if strings.Contains(e, "No LLM providers configured") {
				t.Errorf("unexpected error: %s", e)
			}
		}
	})

	t.Run("warns about Ollama model without endpoint", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvBedrockRegion)
		env.Unset(EnvOllamaEndpoint)
		env.Set(EnvOllamaModel, "llama3.1:latest")

		errors := ValidateEnvironment()

		hasOllamaError := false
		for _, e := range errors {
			if strings.Contains(e, "OLLAMA_MODEL") && strings.Contains(e, "OLLAMA_ENDPOINT") {
				hasOllamaError = true
				break
			}
		}
		if !hasOllamaError {
			t.Error("expected warning about Ollama model without endpoint")
		}
	})
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"short", "***"},
		{"12345678", "***"},
		{"123456789", "1234...6789"},
		{"sk-ant-api03-test-key-12345678", "sk-a...5678"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := maskAPIKey(tt.input)
			if result != tt.expected {
				t.Errorf("maskAPIKey(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestQuickBootstrap(t *testing.T) {
	t.Run("returns error when no providers configured", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)

		_, err := QuickBootstrap()
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		if !strings.Contains(err.Error(), "no providers available") {
			t.Errorf("expected 'no providers available' error, got: %v", err)
		}
	})

	t.Run("returns router with providers", func(t *testing.T) {
		env := newTestEnvHelper(t)
		defer env.Restore()

		// Create mock Ollama server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/tags" {
				resp := map[string]any{"models": []any{}}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		env.Unset(EnvAnthropicAPIKey)
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvBedrockRegion)
		env.Set(EnvOllamaEndpoint, server.URL)

		router, err := QuickBootstrap()
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if router == nil {
			t.Fatal("expected router, got nil")
		}

		// Verify registry has the provider
		if !router.Registry().Has("ollama") {
			t.Error("expected ollama provider in registry")
		}
	})
}

func TestContainsProviderType(t *testing.T) {
	types := []ProviderType{ProviderTypeAnthropic, ProviderTypeOpenAI}

	if !containsProviderType(types, ProviderTypeAnthropic) {
		t.Error("expected Anthropic to be found")
	}

	if !containsProviderType(types, ProviderTypeOpenAI) {
		t.Error("expected OpenAI to be found")
	}

	if containsProviderType(types, ProviderTypeOllama) {
		t.Error("expected Ollama to not be found")
	}

	if containsProviderType(nil, ProviderTypeAnthropic) {
		t.Error("expected nil slice to return false")
	}

	if containsProviderType([]ProviderType{}, ProviderTypeAnthropic) {
		t.Error("expected empty slice to return false")
	}
}

// Helper functions

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
