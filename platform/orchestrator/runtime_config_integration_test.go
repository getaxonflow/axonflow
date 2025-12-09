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
	"context"
	"testing"
)

// clearRuntimeConfigService safely clears the runtime config service for testing.
// This function is needed because runtimeConfigService is now protected by a mutex.
func clearRuntimeConfigService() {
	runtimeConfigMu.Lock()
	runtimeConfigService = nil
	runtimeConfigMu.Unlock()
}

// clearLLMRouter safely clears the LLM router for testing.
func clearLLMRouter() {
	llmRouterMu.Lock()
	llmRouter = nil
	llmRouterMu.Unlock()
}

func TestInitRuntimeConfigService(t *testing.T) {
	// Clear any existing instance
	clearRuntimeConfigService()

	// Initialize without database (env vars only mode)
	svc := InitRuntimeConfigService(nil, false)

	if svc == nil {
		t.Error("Expected non-nil RuntimeConfigService")
	}

	// Verify global instance is set
	if GetRuntimeConfigService() == nil {
		t.Error("Expected GetRuntimeConfigService() to return non-nil after init")
	}
}

func TestLoadLLMConfigFromService_FallbackToEnvVars(t *testing.T) {
	// Clear any existing instance to test fallback
	clearRuntimeConfigService()

	// Use t.Setenv for automatic cleanup
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")

	ctx := context.Background()
	config := LoadLLMConfigFromService(ctx, "test-tenant")

	// Verify it falls back to env vars
	if config.OpenAIKey != "test-openai-key" {
		t.Errorf("Expected OpenAIKey 'test-openai-key', got '%s'", config.OpenAIKey)
	}

	if config.AnthropicKey != "test-anthropic-key" {
		t.Errorf("Expected AnthropicKey 'test-anthropic-key', got '%s'", config.AnthropicKey)
	}
}

func TestLoadLLMConfigFromService_WithService(t *testing.T) {
	// Initialize service in env-var mode (no database)
	InitRuntimeConfigService(nil, false)

	// Use t.Setenv for automatic cleanup
	t.Setenv("BEDROCK_REGION", "us-west-2")
	t.Setenv("BEDROCK_MODEL", "anthropic.claude-3-opus-20240229-v1:0")

	ctx := context.Background()
	config := LoadLLMConfigFromService(ctx, "test-tenant")

	// Service will load from env vars since no database
	if config.BedrockRegion != "us-west-2" {
		t.Errorf("Expected BedrockRegion 'us-west-2', got '%s'", config.BedrockRegion)
	}

	if config.BedrockModel != "anthropic.claude-3-opus-20240229-v1:0" {
		t.Errorf("Expected BedrockModel 'anthropic.claude-3-opus-20240229-v1:0', got '%s'", config.BedrockModel)
	}
}

func TestRefreshLLMConfig_NoServiceIsNoOp(t *testing.T) {
	// Clear service
	clearRuntimeConfigService()

	ctx := context.Background()
	err := RefreshLLMConfig(ctx, "test-tenant")

	if err != nil {
		t.Errorf("Expected no error for refresh without service, got: %v", err)
	}
}

func TestRefreshLLMConfig_WithService(t *testing.T) {
	// Initialize service in env-var mode
	InitRuntimeConfigService(nil, false)

	// Use t.Setenv for automatic cleanup
	t.Setenv("OPENAI_API_KEY", "refresh-test-key")

	ctx := context.Background()
	err := RefreshLLMConfig(ctx, "test-tenant")

	if err != nil {
		t.Errorf("Expected no error for refresh with service, got: %v", err)
	}
}

func TestRefreshLLMConfig_WithRouterReconfiguration(t *testing.T) {
	// Initialize service
	InitRuntimeConfigService(nil, false)

	// Use t.Setenv for automatic cleanup
	t.Setenv("OPENAI_API_KEY", "router-test-key")

	// Clean up router at end of test
	t.Cleanup(func() {
		clearLLMRouter()
	})

	// Create an LLM router using thread-safe setter
	SetLLMRouter(NewLLMRouter(LLMRouterConfig{OpenAIKey: "initial-key"}))

	ctx := context.Background()
	err := RefreshLLMConfig(ctx, "test-tenant")

	if err != nil {
		t.Errorf("Expected no error for refresh with router, got: %v", err)
	}

	// Verify router was reconfigured (it should be non-nil)
	if GetLLMRouter() == nil {
		t.Error("Expected llmRouter to be reconfigured, but it's nil")
	}
}

func TestLoadLLMConfigFromService_AllProviders(t *testing.T) {
	// Initialize service in env-var mode
	InitRuntimeConfigService(nil, false)

	// Use t.Setenv for automatic cleanup of all provider env vars
	t.Setenv("OPENAI_API_KEY", "openai-key-test")
	t.Setenv("ANTHROPIC_API_KEY", "anthropic-key-test")
	t.Setenv("BEDROCK_REGION", "eu-west-1")
	t.Setenv("BEDROCK_MODEL", "claude-3-5-sonnet")
	t.Setenv("OLLAMA_ENDPOINT", "http://localhost:11434")
	t.Setenv("OLLAMA_MODEL", "llama3:70b")

	ctx := context.Background()
	config := LoadLLMConfigFromService(ctx, "multi-provider-tenant")

	// Verify all providers loaded
	if config.OpenAIKey != "openai-key-test" {
		t.Errorf("Expected OpenAIKey 'openai-key-test', got '%s'", config.OpenAIKey)
	}
	if config.AnthropicKey != "anthropic-key-test" {
		t.Errorf("Expected AnthropicKey 'anthropic-key-test', got '%s'", config.AnthropicKey)
	}
	if config.BedrockRegion != "eu-west-1" {
		t.Errorf("Expected BedrockRegion 'eu-west-1', got '%s'", config.BedrockRegion)
	}
	if config.BedrockModel != "claude-3-5-sonnet" {
		t.Errorf("Expected BedrockModel 'claude-3-5-sonnet', got '%s'", config.BedrockModel)
	}
	if config.OllamaEndpoint != "http://localhost:11434" {
		t.Errorf("Expected OllamaEndpoint 'http://localhost:11434', got '%s'", config.OllamaEndpoint)
	}
	if config.OllamaModel != "llama3:70b" {
		t.Errorf("Expected OllamaModel 'llama3:70b', got '%s'", config.OllamaModel)
	}
}

func TestLoadLLMConfigFromService_NoProvidersConfigured(t *testing.T) {
	// Initialize service in env-var mode
	InitRuntimeConfigService(nil, false)

	// Use t.Setenv with empty strings to clear env vars
	// t.Setenv automatically saves and restores the original values
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("BEDROCK_REGION", "")
	t.Setenv("OLLAMA_ENDPOINT", "")

	ctx := context.Background()
	config := LoadLLMConfigFromService(ctx, "no-provider-tenant")

	// All should be empty
	if config.OpenAIKey != "" {
		t.Errorf("Expected empty OpenAIKey, got '%s'", config.OpenAIKey)
	}
	if config.AnthropicKey != "" {
		t.Errorf("Expected empty AnthropicKey, got '%s'", config.AnthropicKey)
	}
	if config.BedrockRegion != "" {
		t.Errorf("Expected empty BedrockRegion, got '%s'", config.BedrockRegion)
	}
	if config.OllamaEndpoint != "" {
		t.Errorf("Expected empty OllamaEndpoint, got '%s'", config.OllamaEndpoint)
	}
}

func TestInitRuntimeConfigService_SelfHostedMode(t *testing.T) {
	// Clear existing instance
	clearRuntimeConfigService()

	// Initialize in self-hosted mode
	svc := InitRuntimeConfigService(nil, true)

	if svc == nil {
		t.Error("Expected non-nil RuntimeConfigService in self-hosted mode")
	}

	// Verify global instance is set
	if GetRuntimeConfigService() == nil {
		t.Error("Expected GetRuntimeConfigService() to return non-nil")
	}
}

func TestGetRuntimeConfigService_BeforeInit(t *testing.T) {
	// Clear existing instance
	clearRuntimeConfigService()

	// Should return nil before initialization
	if GetRuntimeConfigService() != nil {
		t.Error("Expected GetRuntimeConfigService() to return nil before init")
	}
}

// Test provider name validation
func TestIsValidLLMProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		want     bool
	}{
		{"valid openai", "openai", true},
		{"valid anthropic", "anthropic", true},
		{"valid bedrock", "bedrock", true},
		{"valid ollama", "ollama", true},
		{"invalid provider", "invalid", false},
		{"empty provider", "", false},
		{"case sensitive OpenAI", "OpenAI", false},
		{"typo openaai", "openaai", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidLLMProvider(tt.provider); got != tt.want {
				t.Errorf("isValidLLMProvider(%q) = %v, want %v", tt.provider, got, tt.want)
			}
		})
	}
}

// Test provider constants
func TestProviderConstants(t *testing.T) {
	// Verify constants match expected values
	if ProviderOpenAI != "openai" {
		t.Errorf("ProviderOpenAI = %q, want %q", ProviderOpenAI, "openai")
	}
	if ProviderAnthropic != "anthropic" {
		t.Errorf("ProviderAnthropic = %q, want %q", ProviderAnthropic, "anthropic")
	}
	if ProviderBedrock != "bedrock" {
		t.Errorf("ProviderBedrock = %q, want %q", ProviderBedrock, "bedrock")
	}
	if ProviderOllama != "ollama" {
		t.Errorf("ProviderOllama = %q, want %q", ProviderOllama, "ollama")
	}

	// Verify ValidLLMProviders contains all constants
	if len(ValidLLMProviders) != 4 {
		t.Errorf("ValidLLMProviders has %d entries, want 4", len(ValidLLMProviders))
	}
}

// Test thread-safe getter/setter for LLM router
func TestGetSetLLMRouter(t *testing.T) {
	// Clear router
	clearLLMRouter()
	t.Cleanup(func() {
		clearLLMRouter()
	})

	// Initially should be nil
	if GetLLMRouter() != nil {
		t.Error("Expected GetLLMRouter() to return nil initially")
	}

	// Set a router
	router := NewLLMRouter(LLMRouterConfig{OpenAIKey: "test-key"})
	SetLLMRouter(router)

	// Should return the router we set
	if GetLLMRouter() != router {
		t.Error("Expected GetLLMRouter() to return the router we set")
	}
}
