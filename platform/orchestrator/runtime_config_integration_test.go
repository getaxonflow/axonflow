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
	"os"
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

// =============================================================================
// Config File Loader Tests (ADR-007 Phase 9)
// =============================================================================

func TestSetConfigFileLoaderFromEnv_NoEnvVar(t *testing.T) {
	InitRuntimeConfigService(nil, false)
	t.Cleanup(func() { clearRuntimeConfigService() })

	t.Setenv("AXONFLOW_CONFIG_FILE", "")
	t.Setenv("AXONFLOW_LLM_CONFIG_FILE", "")

	result := SetConfigFileLoaderFromEnv()
	if result != "" {
		t.Errorf("Expected empty string when no env var set, got %q", result)
	}
}

func TestSetConfigFileLoaderFromEnv_FileNotFound(t *testing.T) {
	InitRuntimeConfigService(nil, false)
	t.Cleanup(func() { clearRuntimeConfigService() })

	t.Setenv("AXONFLOW_CONFIG_FILE", "/nonexistent/path/config.yaml")

	result := SetConfigFileLoaderFromEnv()
	if result != "" {
		t.Errorf("Expected empty string for non-existent file, got %q", result)
	}
}

func TestSetConfigFileLoaderFromEnv_PathIsDirectory(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	// Use temp directory as config file path (should fail - it's a directory)
	tmpDir := t.TempDir()
	t.Setenv("AXONFLOW_CONFIG_FILE", tmpDir)

	result := SetConfigFileLoaderFromEnv()
	if result != "" {
		t.Errorf("Expected empty string when path is a directory, got %q", result)
	}
}

func TestSetConfigFileLoaderFromEnv_InvalidYAML(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	// Create a temp file with invalid YAML
	tmpFile := createTempConfigFile(t, `invalid: yaml: content: [unclosed`)
	t.Setenv("AXONFLOW_CONFIG_FILE", tmpFile)

	result := SetConfigFileLoaderFromEnv()
	if result != "" {
		t.Errorf("Expected empty string for invalid YAML, got %q", result)
	}
}

func TestSetConfigFileLoaderFromEnv_ServiceNotInitialized(t *testing.T) {
	clearRuntimeConfigService()

	tmpFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  openai:
    enabled: true
    credentials:
      api_key: test-key`)
	t.Setenv("AXONFLOW_CONFIG_FILE", tmpFile)

	result := SetConfigFileLoaderFromEnv()
	if result != "" {
		t.Errorf("Expected empty string when service not initialized, got %q", result)
	}
}

func TestSetConfigFileLoaderFromEnv_ValidConfigFile(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	tmpFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  openai:
    enabled: true
    credentials:
      api_key: config-file-openai-key`)
	t.Setenv("AXONFLOW_CONFIG_FILE", tmpFile)

	result := SetConfigFileLoaderFromEnv()
	if result != tmpFile {
		t.Errorf("Expected config file path %q, got %q", tmpFile, result)
	}
}

func TestSetConfigFileLoaderFromEnv_AlternativeEnvVar(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	tmpFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  bedrock:
    enabled: true
    config:
      region: us-west-2
      model: anthropic.claude-3-5-sonnet-20240620-v1:0`)
	t.Setenv("AXONFLOW_CONFIG_FILE", "")
	t.Setenv("AXONFLOW_LLM_CONFIG_FILE", tmpFile)

	result := SetConfigFileLoaderFromEnv()
	if result != tmpFile {
		t.Errorf("Expected config file from AXONFLOW_LLM_CONFIG_FILE %q, got %q", tmpFile, result)
	}
}

func TestSetConfigFileLoaderFromEnv_PrimaryEnvVarTakesPrecedence(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	primaryFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  openai:
    enabled: true
    credentials:
      api_key: primary-key`)
	alternativeFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  anthropic:
    enabled: true
    credentials:
      api_key: alternative-key`)

	t.Setenv("AXONFLOW_CONFIG_FILE", primaryFile)
	t.Setenv("AXONFLOW_LLM_CONFIG_FILE", alternativeFile)

	result := SetConfigFileLoaderFromEnv()
	if result != primaryFile {
		t.Errorf("Expected primary config file %q to take precedence, got %q", primaryFile, result)
	}
}

func TestLoadLLMConfigFromService_WithConfigFile(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("BEDROCK_REGION", "")
	t.Setenv("OLLAMA_ENDPOINT", "")

	tmpFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  openai:
    enabled: true
    credentials:
      api_key: config-file-openai-key-12345
  anthropic:
    enabled: true
    credentials:
      api_key: config-file-anthropic-key-67890`)
	t.Setenv("AXONFLOW_CONFIG_FILE", tmpFile)

	result := SetConfigFileLoaderFromEnv()
	if result == "" {
		t.Fatal("Failed to set config file loader")
	}

	ctx := context.Background()
	config := LoadLLMConfigFromService(ctx, "test-tenant")

	if config.OpenAIKey != "config-file-openai-key-12345" {
		t.Errorf("Expected OpenAIKey 'config-file-openai-key-12345', got '%s'", config.OpenAIKey)
	}
	if config.AnthropicKey != "config-file-anthropic-key-67890" {
		t.Errorf("Expected AnthropicKey 'config-file-anthropic-key-67890', got '%s'", config.AnthropicKey)
	}
}

func TestLoadLLMConfigFromService_ConfigFileWithAllProviders(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("BEDROCK_REGION", "")
	t.Setenv("OLLAMA_ENDPOINT", "")

	tmpFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  openai:
    enabled: true
    credentials:
      api_key: file-openai-key
  anthropic:
    enabled: true
    credentials:
      api_key: file-anthropic-key
  bedrock:
    enabled: true
    config:
      region: eu-central-1
      model: anthropic.claude-3-opus-20240229-v1:0
  ollama:
    enabled: true
    config:
      endpoint: http://ollama.local:11434
      model: llama3.1:70b`)
	t.Setenv("AXONFLOW_CONFIG_FILE", tmpFile)
	SetConfigFileLoaderFromEnv()

	ctx := context.Background()
	config := LoadLLMConfigFromService(ctx, "all-providers-tenant")

	if config.OpenAIKey != "file-openai-key" {
		t.Errorf("Expected OpenAIKey 'file-openai-key', got '%s'", config.OpenAIKey)
	}
	if config.AnthropicKey != "file-anthropic-key" {
		t.Errorf("Expected AnthropicKey 'file-anthropic-key', got '%s'", config.AnthropicKey)
	}
	if config.BedrockRegion != "eu-central-1" {
		t.Errorf("Expected BedrockRegion 'eu-central-1', got '%s'", config.BedrockRegion)
	}
	if config.BedrockModel != "anthropic.claude-3-opus-20240229-v1:0" {
		t.Errorf("Expected BedrockModel 'anthropic.claude-3-opus-20240229-v1:0', got '%s'", config.BedrockModel)
	}
	if config.OllamaEndpoint != "http://ollama.local:11434" {
		t.Errorf("Expected OllamaEndpoint 'http://ollama.local:11434', got '%s'", config.OllamaEndpoint)
	}
	if config.OllamaModel != "llama3.1:70b" {
		t.Errorf("Expected OllamaModel 'llama3.1:70b', got '%s'", config.OllamaModel)
	}
}

func TestLoadLLMConfigFromService_ConfigFileWithEnvVarExpansion(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	t.Setenv("TEST_OPENAI_API_KEY", "expanded-openai-key-from-env")
	t.Setenv("TEST_ANTHROPIC_API_KEY", "expanded-anthropic-key-from-env")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("BEDROCK_REGION", "")
	t.Setenv("OLLAMA_ENDPOINT", "")

	tmpFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  openai:
    enabled: true
    credentials:
      api_key: ${TEST_OPENAI_API_KEY}
  anthropic:
    enabled: true
    credentials:
      api_key: ${TEST_ANTHROPIC_API_KEY}`)
	t.Setenv("AXONFLOW_CONFIG_FILE", tmpFile)
	SetConfigFileLoaderFromEnv()

	ctx := context.Background()
	config := LoadLLMConfigFromService(ctx, "env-expansion-tenant")

	if config.OpenAIKey != "expanded-openai-key-from-env" {
		t.Errorf("Expected OpenAIKey 'expanded-openai-key-from-env', got '%s'", config.OpenAIKey)
	}
	if config.AnthropicKey != "expanded-anthropic-key-from-env" {
		t.Errorf("Expected AnthropicKey 'expanded-anthropic-key-from-env', got '%s'", config.AnthropicKey)
	}
}

func TestReloadConfigFile_ServiceNotInitialized(t *testing.T) {
	clearRuntimeConfigService()

	err := ReloadConfigFile()
	if err != nil {
		t.Errorf("Expected no error when service not initialized, got: %v", err)
	}
}

func TestReloadConfigFile_WithService(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	err := ReloadConfigFile()
	if err != nil {
		t.Errorf("Expected no error for reload with service, got: %v", err)
	}
}

func TestThreeTierPriority_ConfigFileOverEnvVars(t *testing.T) {
	InitRuntimeConfigService(nil, true)
	t.Cleanup(func() { clearRuntimeConfigService() })

	t.Setenv("OPENAI_API_KEY", "env-var-openai-key")
	t.Setenv("ANTHROPIC_API_KEY", "env-var-anthropic-key")

	tmpFile := createTempConfigFile(t, `version: "1.0"
llm_providers:
  openai:
    enabled: true
    credentials:
      api_key: config-file-openai-wins`)
	t.Setenv("AXONFLOW_CONFIG_FILE", tmpFile)
	SetConfigFileLoaderFromEnv()

	ctx := context.Background()
	config := LoadLLMConfigFromService(ctx, "priority-test-tenant")

	if config.OpenAIKey != "config-file-openai-wins" {
		t.Errorf("Expected OpenAIKey from config file 'config-file-openai-wins', got '%s'", config.OpenAIKey)
	}
}

// Helper function to create temporary config files for testing
func createTempConfigFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "axonflow-test-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp config file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp config file: %v", err)
	}
	return tmpFile.Name()
}
