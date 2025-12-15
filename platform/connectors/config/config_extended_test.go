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

package config

import (
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

// TestLoadFromEnv tests the LoadFromEnv function
func TestLoadFromEnv(t *testing.T) {
	tests := []struct {
		name           string
		connectorName  string
		connectorType  string
		envVars        map[string]string
		wantErr        bool
		errContains    string
		validateConfig func(*testing.T, interface{})
	}{
		{
			name:          "success with all required fields",
			connectorName: "test_conn",
			connectorType: "postgres",
			envVars: map[string]string{
				"MCP_test_conn_URL": "postgres://localhost:5432/test",
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg interface{}) {
				config := cfg.(map[string]interface{})
				if config["ConnectionURL"] != "postgres://localhost:5432/test" {
					t.Errorf("Expected connection URL to be set")
				}
			},
		},
		{
			name:          "success with timeout",
			connectorName: "test_timeout",
			connectorType: "postgres",
			envVars: map[string]string{
				"MCP_test_timeout_URL":     "postgres://localhost:5432/test",
				"MCP_test_timeout_TIMEOUT": "10s",
			},
			wantErr: false,
		},
		{
			name:          "invalid timeout format",
			connectorName: "test_bad_timeout",
			connectorType: "postgres",
			envVars: map[string]string{
				"MCP_test_bad_timeout_URL":     "postgres://localhost:5432/test",
				"MCP_test_bad_timeout_TIMEOUT": "not-a-duration",
			},
			wantErr:     true,
			errContains: "invalid timeout format",
		},
		{
			name:          "invalid max_retries format",
			connectorName: "test_bad_retries",
			connectorType: "postgres",
			envVars: map[string]string{
				"MCP_test_bad_retries_URL":         "postgres://localhost:5432/test",
				"MCP_test_bad_retries_MAX_RETRIES": "not-a-number",
			},
			wantErr:     true,
			errContains: "invalid max_retries format",
		},
		{
			name:          "missing URL",
			connectorName: "test_no_url",
			connectorType: "postgres",
			envVars:       map[string]string{},
			wantErr:       true,
			errContains:   "missing required environment variable",
		},
		{
			name:          "success with credentials",
			connectorName: "test_creds",
			connectorType: "postgres",
			envVars: map[string]string{
				"MCP_test_creds_URL":      "postgres://localhost:5432/test",
				"MCP_test_creds_USERNAME": "testuser",
				"MCP_test_creds_PASSWORD": "testpass",
				"MCP_test_creds_API_KEY":  "testapikey",
			},
			wantErr: false,
		},
		{
			name:          "success with tenant ID",
			connectorName: "test_tenant",
			connectorType: "postgres",
			envVars: map[string]string{
				"MCP_test_tenant_URL":       "postgres://localhost:5432/test",
				"MCP_test_tenant_TENANT_ID": "tenant-123",
			},
			wantErr: false,
		},
		{
			name:          "success with max retries",
			connectorName: "test_retries",
			connectorType: "postgres",
			envVars: map[string]string{
				"MCP_test_retries_URL":         "postgres://localhost:5432/test",
				"MCP_test_retries_MAX_RETRIES": "5",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("failed to set env: %v", err)
				}
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			config, err := LoadFromEnv(tt.connectorName, tt.connectorType)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if config.Name != tt.connectorName {
				t.Errorf("expected name %q, got %q", tt.connectorName, config.Name)
			}
			if config.Type != tt.connectorType {
				t.Errorf("expected type %q, got %q", tt.connectorType, config.Type)
			}
		})
	}
}

// TestLoadPostgresConfig tests PostgreSQL config loading
func TestLoadPostgresConfig(t *testing.T) {
	tests := []struct {
		name          string
		connectorName string
		envVars       map[string]string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "success with MCP prefix",
			connectorName: "test_pg",
			envVars: map[string]string{
				"MCP_test_pg_URL": "postgres://localhost:5432/test",
			},
			wantErr: false,
		},
		{
			name:          "fallback to DATABASE_URL",
			connectorName: "test_pg_fallback",
			envVars: map[string]string{
				"DATABASE_URL": "postgres://localhost:5432/fallback",
			},
			wantErr: false,
		},
		{
			name:          "missing all URLs",
			connectorName: "test_pg_missing",
			envVars:       map[string]string{},
			wantErr:       true,
			errContains:   "no PostgreSQL configuration found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear any existing env vars
			os.Unsetenv("DATABASE_URL")
			os.Unsetenv("MCP_" + tt.connectorName + "_URL")

			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("failed to set env: %v", err)
				}
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			config, err := LoadPostgresConfig(tt.connectorName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if config.Type != "postgres" {
				t.Errorf("expected type 'postgres', got %q", config.Type)
			}

			// Check defaults for fallback case
			if tt.name == "fallback to DATABASE_URL" {
				if config.Timeout != 5*time.Second {
					t.Errorf("expected default timeout of 5s")
				}
				if config.MaxRetries != 3 {
					t.Errorf("expected default max retries of 3")
				}
				if config.TenantID != "*" {
					t.Errorf("expected default tenant ID of *")
				}
			}
		})
	}
}

// TestLoadCassandraConfig tests Cassandra config loading
func TestLoadCassandraConfig(t *testing.T) {
	tests := []struct {
		name          string
		connectorName string
		envVars       map[string]string
		wantErr       bool
	}{
		{
			name:          "success with basic config",
			connectorName: "test_cass",
			envVars: map[string]string{
				"MCP_test_cass_URL": "cassandra://localhost:9042",
			},
			wantErr: false,
		},
		{
			name:          "success with keyspace and consistency",
			connectorName: "test_cass_full",
			envVars: map[string]string{
				"MCP_test_cass_full_URL":         "cassandra://localhost:9042",
				"MCP_test_cass_full_KEYSPACE":    "test_keyspace",
				"MCP_test_cass_full_CONSISTENCY": "ONE",
			},
			wantErr: false,
		},
		{
			name:          "missing URL",
			connectorName: "test_cass_missing",
			envVars:       map[string]string{},
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("failed to set env: %v", err)
				}
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			config, err := LoadCassandraConfig(tt.connectorName)

			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !tt.wantErr {
				if config.Type != "cassandra" {
					t.Errorf("expected type 'cassandra', got %q", config.Type)
				}

				// Check consistency default
				if tt.name == "success with basic config" {
					if config.Options["consistency"] != "QUORUM" {
						t.Errorf("expected default consistency 'QUORUM'")
					}
				}
			}
		})
	}
}

// TestLoadSlackConfig tests Slack config loading
func TestLoadSlackConfig(t *testing.T) {
	tests := []struct {
		name          string
		connectorName string
		envVars       map[string]string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "success with bot token",
			connectorName: "test_slack",
			envVars: map[string]string{
				"MCP_test_slack_BOT_TOKEN": "xoxb-test-token",
			},
			wantErr: false,
		},
		{
			name:          "success with custom base URL",
			connectorName: "test_slack_custom",
			envVars: map[string]string{
				"MCP_test_slack_custom_BOT_TOKEN": "xoxb-test-token",
				"MCP_test_slack_custom_BASE_URL":  "https://custom.slack.com/api",
			},
			wantErr: false,
		},
		{
			name:          "missing bot token",
			connectorName: "test_slack_missing",
			envVars:       map[string]string{},
			wantErr:       true,
			errContains:   "missing required environment variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("failed to set env: %v", err)
				}
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			config, err := LoadSlackConfig(tt.connectorName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if config.Type != "slack" {
				t.Errorf("expected type 'slack', got %q", config.Type)
			}
			if config.ConnectionURL != "https://slack.com/api" {
				t.Errorf("expected connection URL 'https://slack.com/api', got %q", config.ConnectionURL)
			}
			if config.Timeout != 30*time.Second {
				t.Errorf("expected timeout 30s, got %v", config.Timeout)
			}
		})
	}
}

// TestLoadSalesforceConfig tests Salesforce config loading
func TestLoadSalesforceConfig(t *testing.T) {
	tests := []struct {
		name          string
		connectorName string
		envVars       map[string]string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "success with all credentials",
			connectorName: "test_sf",
			envVars: map[string]string{
				"MCP_test_sf_CLIENT_ID":     "client-id",
				"MCP_test_sf_CLIENT_SECRET": "client-secret",
				"MCP_test_sf_USERNAME":      "user@example.com",
				"MCP_test_sf_PASSWORD":      "password",
			},
			wantErr: false,
		},
		{
			name:          "success with optional fields",
			connectorName: "test_sf_full",
			envVars: map[string]string{
				"MCP_test_sf_full_CLIENT_ID":      "client-id",
				"MCP_test_sf_full_CLIENT_SECRET":  "client-secret",
				"MCP_test_sf_full_USERNAME":       "user@example.com",
				"MCP_test_sf_full_PASSWORD":       "password",
				"MCP_test_sf_full_SECURITY_TOKEN": "security-token",
				"MCP_test_sf_full_INSTANCE_URL":   "https://custom.salesforce.com",
			},
			wantErr: false,
		},
		{
			name:          "missing credentials",
			connectorName: "test_sf_missing",
			envVars: map[string]string{
				"MCP_test_sf_missing_CLIENT_ID": "client-id",
				// Missing other required fields
			},
			wantErr:     true,
			errContains: "missing required Salesforce credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("failed to set env: %v", err)
				}
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			config, err := LoadSalesforceConfig(tt.connectorName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if config.Type != "salesforce" {
				t.Errorf("expected type 'salesforce', got %q", config.Type)
			}
		})
	}
}

// TestLoadAmadeusConfig tests Amadeus config loading
func TestLoadAmadeusConfig(t *testing.T) {
	tests := []struct {
		name          string
		connectorName string
		envVars       map[string]string
		wantErr       bool
		errContains   string
		checkURL      string
	}{
		{
			name:          "success with test environment",
			connectorName: "test_amadeus",
			envVars: map[string]string{
				"AMADEUS_API_KEY_TEST":    "test-key",
				"AMADEUS_API_SECRET_TEST": "test-secret",
			},
			wantErr:  false,
			checkURL: "https://test.api.amadeus.com",
		},
		{
			name:          "success with production environment",
			connectorName: "test_amadeus_prod",
			envVars: map[string]string{
				"MCP_test_amadeus_prod_ENVIRONMENT": "production",
				"AMADEUS_API_KEY_PROD":              "prod-key",
				"AMADEUS_API_SECRET_PROD":           "prod-secret",
			},
			wantErr:  false,
			checkURL: "https://api.amadeus.com",
		},
		{
			name:          "success with prefixed credentials",
			connectorName: "test_amadeus_prefix",
			envVars: map[string]string{
				"MCP_test_amadeus_prefix_ENVIRONMENT":     "test",
				"MCP_test_amadeus_prefix_API_KEY_TEST":    "prefix-key",
				"MCP_test_amadeus_prefix_API_SECRET_TEST": "prefix-secret",
			},
			wantErr:  false,
			checkURL: "https://test.api.amadeus.com",
		},
		{
			name:          "success with AMADEUS_ENV",
			connectorName: "test_amadeus_env",
			envVars: map[string]string{
				"AMADEUS_ENV":             "production",
				"AMADEUS_API_KEY_PROD":    "prod-key",
				"AMADEUS_API_SECRET_PROD": "prod-secret",
			},
			wantErr:  false,
			checkURL: "https://api.amadeus.com",
		},
		{
			name:          "success with custom URLs",
			connectorName: "test_amadeus_custom",
			envVars: map[string]string{
				"AMADEUS_API_KEY_TEST":    "test-key",
				"AMADEUS_API_SECRET_TEST": "test-secret",
				"AMADEUS_URL_TEST":        "https://custom.amadeus.com",
			},
			wantErr:  false,
			checkURL: "https://custom.amadeus.com",
		},
		{
			name:          "invalid environment defaults to test",
			connectorName: "test_amadeus_invalid",
			envVars: map[string]string{
				"MCP_test_amadeus_invalid_ENVIRONMENT": "invalid",
				"AMADEUS_API_KEY_TEST":                 "test-key",
				"AMADEUS_API_SECRET_TEST":              "test-secret",
			},
			wantErr:  false,
			checkURL: "https://test.api.amadeus.com",
		},
		{
			name:          "missing credentials for test",
			connectorName: "test_amadeus_missing",
			envVars:       map[string]string{},
			wantErr:       true,
			errContains:   "missing required Amadeus credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all possible Amadeus env vars
			os.Unsetenv("AMADEUS_ENV")
			os.Unsetenv("AMADEUS_API_KEY_TEST")
			os.Unsetenv("AMADEUS_API_SECRET_TEST")
			os.Unsetenv("AMADEUS_API_KEY_PROD")
			os.Unsetenv("AMADEUS_API_SECRET_PROD")
			os.Unsetenv("AMADEUS_URL_TEST")
			os.Unsetenv("AMADEUS_URL_PROD")

			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("failed to set env: %v", err)
				}
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			config, err := LoadAmadeusConfig(tt.connectorName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if config.Type != "amadeus" {
				t.Errorf("expected type 'amadeus', got %q", config.Type)
			}
			if tt.checkURL != "" && config.ConnectionURL != tt.checkURL {
				t.Errorf("expected URL %q, got %q", tt.checkURL, config.ConnectionURL)
			}
		})
	}
}

// TestValidateConfig tests config validation
func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name: "valid postgres config",
			config: map[string]interface{}{
				"Name":          "test",
				"Type":          "postgres",
				"ConnectionURL": "postgres://localhost:5432/test",
				"Timeout":       5 * time.Second,
				"MaxRetries":    3,
			},
			wantErr: false,
		},
		{
			name: "valid API-based config (amadeus)",
			config: map[string]interface{}{
				"Name":       "test-amadeus",
				"Type":       "amadeus",
				"Timeout":    30 * time.Second,
				"MaxRetries": 3,
			},
			wantErr: false,
		},
		{
			name: "valid API-based config (slack)",
			config: map[string]interface{}{
				"Name":       "test-slack",
				"Type":       "slack",
				"Timeout":    30 * time.Second,
				"MaxRetries": 3,
			},
			wantErr: false,
		},
		{
			name: "valid API-based config (salesforce)",
			config: map[string]interface{}{
				"Name":       "test-salesforce",
				"Type":       "salesforce",
				"Timeout":    30 * time.Second,
				"MaxRetries": 3,
			},
			wantErr: false,
		},
		{
			name: "missing name",
			config: map[string]interface{}{
				"Type":          "postgres",
				"ConnectionURL": "postgres://localhost:5432/test",
				"Timeout":       5 * time.Second,
				"MaxRetries":    3,
			},
			wantErr:     true,
			errContains: "connector name is required",
		},
		{
			name: "missing type",
			config: map[string]interface{}{
				"Name":          "test",
				"ConnectionURL": "postgres://localhost:5432/test",
				"Timeout":       5 * time.Second,
				"MaxRetries":    3,
			},
			wantErr:     true,
			errContains: "connector type is required",
		},
		{
			name: "missing URL for postgres",
			config: map[string]interface{}{
				"Name":       "test",
				"Type":       "postgres",
				"Timeout":    5 * time.Second,
				"MaxRetries": 3,
			},
			wantErr:     true,
			errContains: "connection URL is required",
		},
		{
			name: "zero timeout",
			config: map[string]interface{}{
				"Name":          "test",
				"Type":          "postgres",
				"ConnectionURL": "postgres://localhost:5432/test",
				"Timeout":       time.Duration(0),
				"MaxRetries":    3,
			},
			wantErr:     true,
			errContains: "timeout must be positive",
		},
		{
			name: "negative timeout",
			config: map[string]interface{}{
				"Name":          "test",
				"Type":          "postgres",
				"ConnectionURL": "postgres://localhost:5432/test",
				"Timeout":       -1 * time.Second,
				"MaxRetries":    3,
			},
			wantErr:     true,
			errContains: "timeout must be positive",
		},
		{
			name: "negative max retries",
			config: map[string]interface{}{
				"Name":          "test",
				"Type":          "postgres",
				"ConnectionURL": "postgres://localhost:5432/test",
				"Timeout":       5 * time.Second,
				"MaxRetries":    -1,
			},
			wantErr:     true,
			errContains: "max retries cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createConnectorConfig(tt.config)
			err := ValidateConfig(cfg)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Helper function to create ConnectorConfig from map
func createConnectorConfig(m map[string]interface{}) *base.ConnectorConfig {
	cfg := &base.ConnectorConfig{
		Credentials: make(map[string]string),
		Options:     make(map[string]interface{}),
	}
	if v, ok := m["Name"].(string); ok {
		cfg.Name = v
	}
	if v, ok := m["Type"].(string); ok {
		cfg.Type = v
	}
	if v, ok := m["ConnectionURL"].(string); ok {
		cfg.ConnectionURL = v
	}
	if v, ok := m["Timeout"].(time.Duration); ok {
		cfg.Timeout = v
	}
	if v, ok := m["MaxRetries"].(int); ok {
		cfg.MaxRetries = v
	}
	return cfg
}
