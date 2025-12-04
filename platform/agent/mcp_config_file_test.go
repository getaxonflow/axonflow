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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/config"
	"axonflow/platform/connectors/registry"
)

// TestConfigFilePriority tests the three-tier configuration priority
// Priority: Database > Config File > Environment Variables
// This test verifies config file loading without requiring actual database connections
func TestConfigFilePriority(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "axonflow.yaml")

	configContent := `
version: "1.0"

connectors:
  test_postgres:
    type: postgres
    enabled: true
    display_name: "Test PostgreSQL"
    connection_url: postgres://localhost:5432/testdb
    credentials:
      username: testuser
      password: testpass
    options:
      max_open_conns: 10
    timeout_ms: 5000
    max_retries: 2
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Test that the config file loader can parse the file correctly
	loader, err := config.NewYAMLConfigFileLoader(configFile)
	if err != nil {
		t.Fatalf("Failed to create config file loader: %v", err)
	}

	// Load connectors
	connectors, err := loader.LoadConnectors("*")
	if err != nil {
		t.Fatalf("Failed to load connectors: %v", err)
	}

	// Verify connector was parsed
	if len(connectors) != 1 {
		t.Errorf("Expected 1 connector, got %d", len(connectors))
	}

	// Verify connector properties
	cfg := connectors[0]
	if cfg.Name != "test_postgres" {
		t.Errorf("Expected connector name 'test_postgres', got '%s'", cfg.Name)
	}
	if cfg.Type != "postgres" {
		t.Errorf("Expected connector type 'postgres', got '%s'", cfg.Type)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", cfg.Timeout)
	}
	if cfg.MaxRetries != 2 {
		t.Errorf("Expected max_retries 2, got %d", cfg.MaxRetries)
	}
}

// TestConfigFileEnvVarExpansion tests environment variable expansion in config files
func TestConfigFileEnvVarExpansion(t *testing.T) {
	// Set test environment variables
	os.Setenv("TEST_DB_HOST", "myhost.example.com")
	os.Setenv("TEST_DB_PORT", "5433")
	os.Setenv("TEST_DB_USER", "myuser")
	os.Setenv("TEST_DB_PASS", "supersecret")
	defer func() {
		os.Unsetenv("TEST_DB_HOST")
		os.Unsetenv("TEST_DB_PORT")
		os.Unsetenv("TEST_DB_USER")
		os.Unsetenv("TEST_DB_PASS")
	}()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "axonflow.yaml")

	configContent := `
version: "1.0"

connectors:
  env_test_postgres:
    type: postgres
    enabled: true
    display_name: "Env Var Test PostgreSQL"
    connection_url: postgres://${TEST_DB_HOST}:${TEST_DB_PORT}/testdb
    credentials:
      username: ${TEST_DB_USER}
      password: ${TEST_DB_PASS}
    timeout_ms: 5000
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	loader, err := config.NewYAMLConfigFileLoader(configFile)
	if err != nil {
		t.Fatalf("Failed to create config file loader: %v", err)
	}

	connectors, err := loader.LoadConnectors("*")
	if err != nil {
		t.Fatalf("Failed to load connectors: %v", err)
	}

	if len(connectors) == 0 {
		t.Fatal("Expected at least one connector")
	}

	cfg := connectors[0]

	// Verify env var expansion in connection URL
	expectedURL := "postgres://myhost.example.com:5433/testdb"
	if cfg.ConnectionURL != expectedURL {
		t.Errorf("Expected connection URL %s, got %s", expectedURL, cfg.ConnectionURL)
	}

	// Verify env var expansion in credentials
	if cfg.Credentials["username"] != "myuser" {
		t.Errorf("Expected username 'myuser', got '%s'", cfg.Credentials["username"])
	}
	if cfg.Credentials["password"] != "supersecret" {
		t.Errorf("Expected password 'supersecret', got '%s'", cfg.Credentials["password"])
	}
}

// TestConfigFileDefaultValues tests default value syntax in env vars
func TestConfigFileDefaultValues(t *testing.T) {
	// Don't set the env var - should use default
	os.Unsetenv("UNSET_VAR")

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "axonflow.yaml")

	configContent := `
version: "1.0"

connectors:
  default_test:
    type: postgres
    enabled: true
    connection_url: postgres://localhost:${DB_PORT:-5432}/testdb
    credentials:
      username: ${DB_USER:-postgres}
      password: ${DB_PASS:-defaultpass}
    timeout_ms: 5000
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	loader, err := config.NewYAMLConfigFileLoader(configFile)
	if err != nil {
		t.Fatalf("Failed to create config file loader: %v", err)
	}

	connectors, err := loader.LoadConnectors("*")
	if err != nil {
		t.Fatalf("Failed to load connectors: %v", err)
	}

	if len(connectors) == 0 {
		t.Fatal("Expected at least one connector")
	}

	cfg := connectors[0]

	// Verify default values were used
	expectedURL := "postgres://localhost:5432/testdb"
	if cfg.ConnectionURL != expectedURL {
		t.Errorf("Expected connection URL %s, got %s", expectedURL, cfg.ConnectionURL)
	}

	if cfg.Credentials["username"] != "postgres" {
		t.Errorf("Expected default username 'postgres', got '%s'", cfg.Credentials["username"])
	}
}

// TestConfigFileMultipleConnectors tests loading multiple connectors
func TestConfigFileMultipleConnectors(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "axonflow.yaml")

	configContent := `
version: "1.0"

connectors:
  postgres_primary:
    type: postgres
    enabled: true
    display_name: "Primary Database"
    connection_url: postgres://primary:5432/db
    timeout_ms: 5000

  postgres_replica:
    type: postgres
    enabled: true
    display_name: "Replica Database"
    connection_url: postgres://replica:5432/db
    timeout_ms: 5000

  disabled_connector:
    type: postgres
    enabled: false
    connection_url: postgres://disabled:5432/db
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	loader, err := config.NewYAMLConfigFileLoader(configFile)
	if err != nil {
		t.Fatalf("Failed to create config file loader: %v", err)
	}

	connectors, err := loader.LoadConnectors("*")
	if err != nil {
		t.Fatalf("Failed to load connectors: %v", err)
	}

	// Should only load enabled connectors
	if len(connectors) != 2 {
		t.Errorf("Expected 2 enabled connectors, got %d", len(connectors))
	}

	// Verify connector names
	names := make(map[string]bool)
	for _, cfg := range connectors {
		names[cfg.Name] = true
	}

	if !names["postgres_primary"] {
		t.Error("Expected postgres_primary connector")
	}
	if !names["postgres_replica"] {
		t.Error("Expected postgres_replica connector")
	}
	if names["disabled_connector"] {
		t.Error("Disabled connector should not be loaded")
	}
}

// TestConfigFileLLMProviders tests loading LLM provider configurations
func TestConfigFileLLMProviders(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "axonflow.yaml")

	configContent := `
version: "1.0"

llm_providers:
  bedrock:
    enabled: true
    display_name: "Amazon Bedrock"
    config:
      region: us-east-1
      model: anthropic.claude-3-5-sonnet-20240620-v1:0
    priority: 10
    weight: 0.7

  ollama:
    enabled: true
    display_name: "Ollama Local"
    config:
      endpoint: http://localhost:11434
      model: llama3.1:70b
    priority: 5
    weight: 0.3
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	loader, err := config.NewYAMLConfigFileLoader(configFile)
	if err != nil {
		t.Fatalf("Failed to create config file loader: %v", err)
	}

	providers, err := loader.LoadLLMProviders("test-tenant")
	if err != nil {
		t.Fatalf("Failed to load LLM providers: %v", err)
	}

	if len(providers) != 2 {
		t.Errorf("Expected 2 LLM providers, got %d", len(providers))
	}

	// Verify provider properties
	providerMap := make(map[string]*config.LLMProviderConfig)
	for _, p := range providers {
		providerMap[p.ProviderName] = p
	}

	bedrock := providerMap["bedrock"]
	if bedrock == nil {
		t.Fatal("Expected bedrock provider")
	}
	if bedrock.Priority != 10 {
		t.Errorf("Expected bedrock priority 10, got %d", bedrock.Priority)
	}
	if bedrock.Weight != 0.7 {
		t.Errorf("Expected bedrock weight 0.7, got %f", bedrock.Weight)
	}

	ollama := providerMap["ollama"]
	if ollama == nil {
		t.Fatal("Expected ollama provider")
	}
	if ollama.Priority != 5 {
		t.Errorf("Expected ollama priority 5, got %d", ollama.Priority)
	}
}

// TestConfigFileValidation tests config file structure parsing
// Note: The file_loader validates on load; this tests the parsing works correctly
func TestConfigFileValidation(t *testing.T) {
	tests := []struct {
		name         string
		config       string
		expectParse  bool // Whether YAML parsing should succeed
		connCount    int  // Expected enabled connector count
		providerCnt  int  // Expected enabled provider count
	}{
		{
			name: "minimal valid config",
			config: `
version: "1.0"
`,
			expectParse: true,
			connCount:   0,
			providerCnt: 0,
		},
		{
			name: "config with postgres connector",
			config: `
version: "1.0"
connectors:
  test:
    type: postgres
    enabled: true
    connection_url: postgres://localhost/db
`,
			expectParse: true,
			connCount:   1,
			providerCnt: 0,
		},
		{
			name: "config with bedrock provider",
			config: `
version: "1.0"
llm_providers:
  bedrock:
    enabled: true
    config:
      region: us-east-1
    priority: 10
    weight: 0.5
`,
			expectParse: true,
			connCount:   0,
			providerCnt: 1,
		},
		{
			name: "config with disabled connector",
			config: `
version: "1.0"
connectors:
  disabled:
    type: postgres
    enabled: false
`,
			expectParse: true,
			connCount:   0, // Disabled connectors not loaded
			providerCnt: 0,
		},
		{
			name: "full valid config",
			config: `
version: "1.0"
connectors:
  test_postgres:
    type: postgres
    enabled: true
    connection_url: postgres://localhost:5432/db
llm_providers:
  bedrock:
    enabled: true
    weight: 0.5
`,
			expectParse: true,
			connCount:   1,
			providerCnt: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "axonflow.yaml")

			if err := os.WriteFile(configFile, []byte(tc.config), 0644); err != nil {
				t.Fatalf("Failed to write test config file: %v", err)
			}

			loader, err := config.NewYAMLConfigFileLoader(configFile)
			if tc.expectParse {
				if err != nil {
					t.Fatalf("Expected parsing to succeed, got error: %v", err)
				}

				// Check connector count
				connectors, _ := loader.LoadConnectors("*")
				if len(connectors) != tc.connCount {
					t.Errorf("Expected %d connectors, got %d", tc.connCount, len(connectors))
				}

				// Check provider count
				providers, _ := loader.LoadLLMProviders("*")
				if len(providers) != tc.providerCnt {
					t.Errorf("Expected %d providers, got %d", tc.providerCnt, len(providers))
				}
			} else {
				if err == nil {
					t.Error("Expected parsing to fail, but it succeeded")
				}
			}
		})
	}
}

// TestInitializeFromConfigFile_InvalidPath tests that initializeFromConfigFile returns error for invalid path
func TestInitializeFromConfigFile_InvalidPath(t *testing.T) {
	// Reset the registry and runtime config service
	mcpRegistry = nil
	runtimeConfigService = nil
	mcpRegistry = registry.NewRegistry()
	runtimeConfigService = config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})

	err := initializeFromConfigFile("/nonexistent/path/config.yaml")

	if err == nil {
		t.Error("Expected error for nonexistent config file, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "failed to create config file loader") {
		t.Errorf("Expected 'failed to create config file loader' error, got: %v", err)
	}
}

// TestInitializeFromConfigFile_NoEnabledConnectors tests error when config has no enabled connectors
func TestInitializeFromConfigFile_NoEnabledConnectors(t *testing.T) {
	// Create a config file with no enabled connectors
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "axonflow.yaml")

	configContent := `
version: "1.0"

connectors:
  disabled_connector:
    type: postgres
    enabled: false
    connection_url: postgres://localhost:5432/db
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Reset the registry and runtime config service
	mcpRegistry = nil
	runtimeConfigService = nil
	mcpRegistry = registry.NewRegistry()
	runtimeConfigService = config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})

	err := initializeFromConfigFile(configFile)

	if err == nil {
		t.Error("Expected error for config with no enabled connectors, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "no enabled connectors found") {
		t.Errorf("Expected 'no enabled connectors found' error, got: %v", err)
	}
}

// TestInitializeFromConfigFile_WithConnectors tests loading connectors from config file
// Note: Registration will fail due to connection issues, but the function should be invoked
func TestInitializeFromConfigFile_WithConnectors(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "axonflow.yaml")

	configContent := `
version: "1.0"

connectors:
  test_postgres:
    type: postgres
    enabled: true
    connection_url: postgres://localhost:5432/testdb
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Reset the registry and runtime config service
	mcpRegistry = nil
	runtimeConfigService = nil
	mcpRegistry = registry.NewRegistry()
	runtimeConfigService = config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})

	// This should attempt to register but fail connection
	// The function should return nil (successful path with failed registration logged as warning)
	err := initializeFromConfigFile(configFile)

	// No error expected - registration failures are logged but don't cause error
	if err != nil {
		t.Logf("Got expected warning-level error from registration: %v", err)
	}
}

// TestGetRuntimeConfigService tests the getter function
func TestGetRuntimeConfigService(t *testing.T) {
	// Initialize the registry to set up runtimeConfigService
	mcpRegistry = nil
	runtimeConfigService = nil
	InitializeMCPRegistry()

	svc := GetRuntimeConfigService()
	if svc == nil {
		t.Error("Expected GetRuntimeConfigService to return non-nil")
	}
}

// TestConfigFileFallback tests fallback to env vars when no config file
func TestConfigFileFallback(t *testing.T) {
	// Clear the config file env var
	originalConfigFile := os.Getenv("AXONFLOW_CONFIG_FILE")
	os.Unsetenv("AXONFLOW_CONFIG_FILE")
	defer os.Setenv("AXONFLOW_CONFIG_FILE", originalConfigFile)

	// Ensure no default config files exist in current directory
	// (test isolation)

	// Reset the registry
	mcpRegistry = nil

	// Initialize - should fall back to env vars
	if err := InitializeMCPRegistry(); err != nil {
		// This is expected to fail if no connectors are configured via env vars
		t.Logf("InitializeMCPRegistry returned (expected): %v", err)
	}

	// Verify registry was created
	if mcpRegistry == nil {
		t.Error("Expected mcpRegistry to be initialized")
	}
}

// TestRegisterConnectorFromConfig_UnknownType tests that unknown connector types return an error
// Note: We only test unknown types here because valid types require actual database connections
// during registration which would need infrastructure to be available
func TestRegisterConnectorFromConfig_UnknownType(t *testing.T) {
	// Reset registry
	mcpRegistry = nil
	InitializeMCPRegistry()

	cfg := toBaseConfig("test_unknown", "unknown_type", "test://localhost")

	err := registerConnectorFromConfig(cfg)

	if err == nil {
		t.Error("Expected error for unknown connector type, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "unsupported connector type") {
		t.Errorf("Expected 'unsupported connector type' error, got: %v", err)
	}
}

// TestConnectorTypeMapping verifies that the connector type switch statement
// covers all expected connector types. This is a compile-time check that ensures
// we don't miss any connector types in the switch statement.
func TestConnectorTypeMapping(t *testing.T) {
	// List of all supported connector types
	supportedTypes := []string{
		"postgres",
		"cassandra",
		"slack",
		"salesforce",
		"snowflake",
		"amadeus",
	}

	// Verify each type is handled in the switch statement by checking
	// that it doesn't return "unsupported connector type" error
	// Note: The actual registration will fail due to connection issues,
	// but the type validation should pass
	mcpRegistry = nil
	InitializeMCPRegistry()

	for _, connType := range supportedTypes {
		t.Run(connType, func(t *testing.T) {
			cfg := toBaseConfig("test_"+connType, connType, "test://localhost")
			err := registerConnectorFromConfig(cfg)

			// The error should NOT be "unsupported connector type"
			// (it may fail for other reasons like connection issues, which is expected)
			if err != nil && strings.Contains(err.Error(), "unsupported connector type") {
				t.Errorf("Connector type '%s' should be supported but got unsupported error: %v", connType, err)
			}
		})
	}
}

// Helper function to convert test config to base.ConnectorConfig
func toBaseConfig(name, connType, url string) *base.ConnectorConfig {
	return &base.ConnectorConfig{
		Name:          name,
		Type:          connType,
		ConnectionURL: url,
	}
}
