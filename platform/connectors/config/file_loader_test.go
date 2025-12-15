// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandEnvVars(t *testing.T) {
	// Set test environment variables
	os.Setenv("TEST_VAR", "test_value")
	os.Setenv("OTHER_VAR", "other_value")
	defer os.Unsetenv("TEST_VAR")
	defer os.Unsetenv("OTHER_VAR")

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "dollar brace syntax",
			input:    "prefix ${TEST_VAR} suffix",
			expected: "prefix test_value suffix",
		},
		{
			name:     "dollar syntax",
			input:    "prefix $TEST_VAR suffix",
			expected: "prefix test_value suffix",
		},
		{
			name:     "default value - var exists",
			input:    "${TEST_VAR:-default}",
			expected: "test_value",
		},
		{
			name:     "default value - var not exists",
			input:    "${UNDEFINED_VAR:-default_val}",
			expected: "default_val",
		},
		{
			name:     "undefined var - empty result",
			input:    "${UNDEFINED_VAR}",
			expected: "",
		},
		{
			name:     "multiple vars",
			input:    "${TEST_VAR} and ${OTHER_VAR}",
			expected: "test_value and other_value",
		},
		{
			name:     "no vars",
			input:    "plain text without variables",
			expected: "plain text without variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandEnvVars(tt.input)
			if result != tt.expected {
				t.Errorf("expandEnvVars(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateConfigFile(t *testing.T) {
	tests := []struct {
		name    string
		config  *ConfigFile
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &ConfigFile{
				Version: "1.0",
				Connectors: map[string]ConnectorFileConfig{
					"pg": {Type: "postgres", Enabled: true},
				},
				LLMProviders: map[string]LLMProviderFileConfig{
					"bedrock": {Enabled: true, Weight: 0.5},
				},
			},
			wantErr: false,
		},
		{
			name:    "missing version",
			config:  &ConfigFile{},
			wantErr: true,
			errMsg:  "must specify a version",
		},
		{
			name: "connector missing type",
			config: &ConfigFile{
				Version: "1.0",
				Connectors: map[string]ConnectorFileConfig{
					"invalid": {Enabled: true},
				},
			},
			wantErr: true,
			errMsg:  "must specify a type",
		},
		{
			name: "connector invalid type",
			config: &ConfigFile{
				Version: "1.0",
				Connectors: map[string]ConnectorFileConfig{
					"bad": {Type: "unknown_type", Enabled: true},
				},
			},
			wantErr: true,
			errMsg:  "invalid type",
		},
		{
			name: "invalid LLM provider name",
			config: &ConfigFile{
				Version: "1.0",
				LLMProviders: map[string]LLMProviderFileConfig{
					"invalid_provider": {Enabled: true},
				},
			},
			wantErr: true,
			errMsg:  "invalid LLM provider",
		},
		{
			name: "invalid weight too high",
			config: &ConfigFile{
				Version: "1.0",
				LLMProviders: map[string]LLMProviderFileConfig{
					"bedrock": {Enabled: true, Weight: 1.5},
				},
			},
			wantErr: true,
			errMsg:  "weight must be between 0 and 1",
		},
		{
			name: "invalid weight negative",
			config: &ConfigFile{
				Version: "1.0",
				LLMProviders: map[string]LLMProviderFileConfig{
					"bedrock": {Enabled: true, Weight: -0.5},
				},
			},
			wantErr: true,
			errMsg:  "weight must be between 0 and 1",
		},
		{
			name: "all valid connector types",
			config: &ConfigFile{
				Version: "1.0",
				Connectors: map[string]ConnectorFileConfig{
					"pg":  {Type: "postgres", Enabled: true},
					"c":   {Type: "cassandra", Enabled: true},
					"sf":  {Type: "salesforce", Enabled: true},
					"am":  {Type: "amadeus", Enabled: true},
					"sl":  {Type: "slack", Enabled: true},
					"sn":  {Type: "snowflake", Enabled: true},
					"cus": {Type: "custom", Enabled: true},
				},
			},
			wantErr: false,
		},
		{
			name: "all valid LLM providers",
			config: &ConfigFile{
				Version: "1.0",
				LLMProviders: map[string]LLMProviderFileConfig{
					"bedrock":   {Enabled: true, Weight: 0.25},
					"ollama":    {Enabled: true, Weight: 0.25},
					"openai":    {Enabled: true, Weight: 0.25},
					"anthropic": {Enabled: true, Weight: 0.25},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfigFile(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGenerateExampleConfigFile(t *testing.T) {
	example := GenerateExampleConfigFile()

	// Verify it contains key sections
	expectedSections := []string{
		"version:",
		"connectors:",
		"postgres_main:",
		"salesforce_crm:",
		"amadeus_travel:",
		"llm_providers:",
		"bedrock:",
		"ollama:",
		"openai:",
		"anthropic:",
		"${DATABASE_URL}",
		"${POSTGRES_USER:-postgres}",
	}

	for _, section := range expectedSections {
		if !strings.Contains(example, section) {
			t.Errorf("example config should contain %q", section)
		}
	}

	// Verify it's valid YAML length (should be substantial)
	if len(example) < 1000 {
		t.Errorf("example config seems too short: %d chars", len(example))
	}
}

func TestNewYAMLConfigFileLoader_FileNotFound(t *testing.T) {
	_, err := NewYAMLConfigFileLoader("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestNewYAMLConfigFileLoader_InvalidYAML(t *testing.T) {
	// Create temp file with invalid YAML
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(tmpFile, []byte("invalid: yaml: content: ["), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewYAMLConfigFileLoader(tmpFile)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestNewYAMLConfigFileLoader_ValidConfig(t *testing.T) {
	// Create temp file with valid YAML
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "valid.yaml")
	content := `
version: "1.0"
connectors:
  test_pg:
    type: postgres
    enabled: true
    connection_url: postgres://localhost:5432/test
    timeout_ms: 5000
    max_retries: 2
llm_providers:
  bedrock:
    enabled: true
    priority: 10
    weight: 0.8
`
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	loader, err := NewYAMLConfigFileLoader(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if loader.config == nil {
		t.Error("config should be loaded")
	}
	if loader.config.Version != "1.0" {
		t.Errorf("version = %q, want %q", loader.config.Version, "1.0")
	}
}

func TestYAMLConfigFileLoader_Reload(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	content := `
version: "1.0"
connectors:
  pg:
    type: postgres
    enabled: true
`
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	loader, err := NewYAMLConfigFileLoader(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Modify the file
	newContent := `
version: "2.0"
connectors:
  pg:
    type: postgres
    enabled: false
`
	err = os.WriteFile(tmpFile, []byte(newContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Reload
	err = loader.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	if loader.config.Version != "2.0" {
		t.Errorf("version after reload = %q, want %q", loader.config.Version, "2.0")
	}
}

func TestYAMLConfigFileLoader_LoadConnectors(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	content := `
version: "1.0"
connectors:
  enabled_pg:
    type: postgres
    enabled: true
    display_name: "Enabled PG"
    connection_url: postgres://localhost/db
    credentials:
      username: user
      password: pass
    options:
      max_conns: 10
    timeout_ms: 10000
    max_retries: 5
  disabled_pg:
    type: postgres
    enabled: false
  tenant_specific:
    type: postgres
    enabled: true
    tenant_id: tenant-123
`
	os.WriteFile(tmpFile, []byte(content), 0644)

	loader, _ := NewYAMLConfigFileLoader(tmpFile)

	t.Run("load all connectors", func(t *testing.T) {
		configs, err := loader.LoadConnectors("*")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should only get 2 (enabled connectors)
		if len(configs) != 2 {
			t.Errorf("expected 2 connectors, got %d", len(configs))
		}
	})

	t.Run("load tenant-specific", func(t *testing.T) {
		configs, err := loader.LoadConnectors("tenant-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should get enabled_pg (wildcard) + tenant_specific
		if len(configs) != 2 {
			t.Errorf("expected 2 connectors, got %d", len(configs))
		}
	})

	t.Run("load different tenant", func(t *testing.T) {
		configs, err := loader.LoadConnectors("other-tenant")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should get only enabled_pg (wildcard)
		if len(configs) != 1 {
			t.Errorf("expected 1 connector, got %d", len(configs))
		}
	})

	t.Run("verify connector config values", func(t *testing.T) {
		configs, _ := loader.LoadConnectors("*")
		var found bool
		for _, cfg := range configs {
			if cfg.Name == "enabled_pg" {
				found = true
				if cfg.Type != "postgres" {
					t.Errorf("Type = %q, want postgres", cfg.Type)
				}
				if cfg.MaxRetries != 5 {
					t.Errorf("MaxRetries = %d, want 5", cfg.MaxRetries)
				}
				if cfg.Credentials["username"] != "user" {
					t.Errorf("username = %q, want user", cfg.Credentials["username"])
				}
			}
		}
		if !found {
			t.Error("enabled_pg not found")
		}
	})

	t.Run("nil config error", func(t *testing.T) {
		loader2 := &YAMLConfigFileLoader{}
		_, err := loader2.LoadConnectors("*")
		if err == nil {
			t.Error("expected error for nil config")
		}
	})
}

func TestYAMLConfigFileLoader_LoadLLMProviders(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	content := `
version: "1.0"
llm_providers:
  bedrock:
    enabled: true
    display_name: "AWS Bedrock"
    config:
      region: us-east-1
      model: claude-3
    credentials:
      aws_access_key: key
    priority: 10
    weight: 0.8
  ollama:
    enabled: false
    display_name: "Ollama"
  openai:
    enabled: true
`
	os.WriteFile(tmpFile, []byte(content), 0644)

	loader, _ := NewYAMLConfigFileLoader(tmpFile)

	t.Run("load enabled providers", func(t *testing.T) {
		configs, err := loader.LoadLLMProviders("test-tenant")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should get 2 enabled providers
		if len(configs) != 2 {
			t.Errorf("expected 2 providers, got %d", len(configs))
		}
	})

	t.Run("verify provider config values", func(t *testing.T) {
		configs, _ := loader.LoadLLMProviders("test-tenant")
		var found bool
		for _, cfg := range configs {
			if cfg.ProviderName == "bedrock" {
				found = true
				if cfg.DisplayName != "AWS Bedrock" {
					t.Errorf("DisplayName = %q, want 'AWS Bedrock'", cfg.DisplayName)
				}
				if cfg.Priority != 10 {
					t.Errorf("Priority = %d, want 10", cfg.Priority)
				}
				if cfg.Weight != 0.8 {
					t.Errorf("Weight = %f, want 0.8", cfg.Weight)
				}
				if cfg.TenantID != "test-tenant" {
					t.Errorf("TenantID = %q, want 'test-tenant'", cfg.TenantID)
				}
			}
		}
		if !found {
			t.Error("bedrock not found")
		}
	})

	t.Run("default values", func(t *testing.T) {
		configs, _ := loader.LoadLLMProviders("test")
		for _, cfg := range configs {
			if cfg.ProviderName == "openai" {
				// Should have default priority and weight
				if cfg.Priority != 5 {
					t.Errorf("default Priority = %d, want 5", cfg.Priority)
				}
				if cfg.Weight != 1.0 {
					t.Errorf("default Weight = %f, want 1.0", cfg.Weight)
				}
			}
		}
	})

	t.Run("nil config error", func(t *testing.T) {
		loader2 := &YAMLConfigFileLoader{}
		_, err := loader2.LoadLLMProviders("test")
		if err == nil {
			t.Error("expected error for nil config")
		}
	})
}

func TestYAMLConfigFileLoader_WithEnvVars(t *testing.T) {
	os.Setenv("TEST_DB_URL", "postgres://testhost:5432/testdb")
	os.Setenv("TEST_USER", "testuser")
	defer os.Unsetenv("TEST_DB_URL")
	defer os.Unsetenv("TEST_USER")

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	content := `
version: "1.0"
connectors:
  pg:
    type: postgres
    enabled: true
    connection_url: ${TEST_DB_URL}
    credentials:
      username: ${TEST_USER}
      password: ${UNDEFINED_PASSWORD:-default_pass}
`
	os.WriteFile(tmpFile, []byte(content), 0644)

	loader, err := NewYAMLConfigFileLoader(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	configs, _ := loader.LoadConnectors("*")
	if len(configs) != 1 {
		t.Fatalf("expected 1 connector, got %d", len(configs))
	}

	cfg := configs[0]
	if cfg.ConnectionURL != "postgres://testhost:5432/testdb" {
		t.Errorf("ConnectionURL = %q, want env var value", cfg.ConnectionURL)
	}
	if cfg.Credentials["username"] != "testuser" {
		t.Errorf("username = %q, want 'testuser'", cfg.Credentials["username"])
	}
	if cfg.Credentials["password"] != "default_pass" {
		t.Errorf("password = %q, want 'default_pass' (default)", cfg.Credentials["password"])
	}
}
