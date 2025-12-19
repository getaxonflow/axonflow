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
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"axonflow/platform/connectors/base"

	"gopkg.in/yaml.v3"
)

// ConfigFile represents the root structure of a configuration file
type ConfigFile struct {
	Version      string                     `yaml:"version"`
	Connectors   map[string]ConnectorFileConfig `yaml:"connectors,omitempty"`
	LLMProviders map[string]LLMProviderFileConfig `yaml:"llm_providers,omitempty"`
}

// ConnectorFileConfig represents a connector configuration in the config file
type ConnectorFileConfig struct {
	Type           string                 `yaml:"type"`
	Enabled        bool                   `yaml:"enabled"`
	DisplayName    string                 `yaml:"display_name,omitempty"`
	Description    string                 `yaml:"description,omitempty"`
	ConnectionURL  string                 `yaml:"connection_url,omitempty"`
	Credentials    map[string]string      `yaml:"credentials,omitempty"`
	Options        map[string]interface{} `yaml:"options,omitempty"`
	TimeoutMs      int                    `yaml:"timeout_ms,omitempty"`
	MaxRetries     int                    `yaml:"max_retries,omitempty"`
	TenantID       string                 `yaml:"tenant_id,omitempty"`
}

// LLMProviderFileConfig represents an LLM provider configuration in the config file
type LLMProviderFileConfig struct {
	Enabled      bool                   `yaml:"enabled"`
	DisplayName  string                 `yaml:"display_name,omitempty"`
	Config       map[string]interface{} `yaml:"config,omitempty"`
	Credentials  map[string]string      `yaml:"credentials,omitempty"`
	Priority     int                    `yaml:"priority,omitempty"`
	Weight       float64                `yaml:"weight,omitempty"`
}

// YAMLConfigFileLoader loads configurations from a YAML file
type YAMLConfigFileLoader struct {
	filePath string
	config   *ConfigFile
}

// NewYAMLConfigFileLoader creates a new YAML config file loader
func NewYAMLConfigFileLoader(filePath string) (*YAMLConfigFileLoader, error) {
	loader := &YAMLConfigFileLoader{
		filePath: filePath,
	}

	// Load and parse the config file
	if err := loader.reload(); err != nil {
		return nil, err
	}

	return loader, nil
}

// reload reads and parses the configuration file
func (l *YAMLConfigFileLoader) reload() error {
	data, err := os.ReadFile(l.filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", l.filePath, err)
	}

	// Expand environment variables in the content
	expanded := expandEnvVars(string(data))

	var config ConfigFile
	if err := yaml.Unmarshal([]byte(expanded), &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	l.config = &config
	return nil
}

// LoadConnectors returns connector configs from the config file
func (l *YAMLConfigFileLoader) LoadConnectors(tenantID string) ([]*base.ConnectorConfig, error) {
	if l.config == nil {
		return nil, fmt.Errorf("config not loaded")
	}

	var configs []*base.ConnectorConfig

	for name, fileConfig := range l.config.Connectors {
		if !fileConfig.Enabled {
			continue
		}

		// Filter by tenant if specified
		cfgTenantID := fileConfig.TenantID
		if cfgTenantID == "" {
			cfgTenantID = "*" // Default to wildcard
		}
		if tenantID != "*" && cfgTenantID != "*" && cfgTenantID != tenantID {
			continue
		}

		timeout := time.Duration(fileConfig.TimeoutMs) * time.Millisecond
		if timeout == 0 {
			timeout = 30 * time.Second
		}

		maxRetries := fileConfig.MaxRetries
		if maxRetries == 0 {
			maxRetries = 3
		}

		options := fileConfig.Options
		if options == nil {
			options = make(map[string]interface{})
		}

		credentials := fileConfig.Credentials
		if credentials == nil {
			credentials = make(map[string]string)
		}

		cfg := &base.ConnectorConfig{
			Name:          name,
			Type:          fileConfig.Type,
			ConnectionURL: fileConfig.ConnectionURL,
			Credentials:   credentials,
			Options:       options,
			Timeout:       timeout,
			MaxRetries:    maxRetries,
			TenantID:      cfgTenantID,
		}

		configs = append(configs, cfg)
	}

	return configs, nil
}

// LoadLLMProviders returns LLM provider configs from the config file
func (l *YAMLConfigFileLoader) LoadLLMProviders(tenantID string) ([]*LLMProviderConfig, error) {
	if l.config == nil {
		return nil, fmt.Errorf("config not loaded")
	}

	var configs []*LLMProviderConfig

	for name, fileConfig := range l.config.LLMProviders {
		if !fileConfig.Enabled {
			continue
		}

		priority := fileConfig.Priority
		if priority == 0 {
			priority = 5 // Default priority
		}

		weight := fileConfig.Weight
		if weight == 0 {
			weight = 1.0 // Default weight
		}

		providerConfig := fileConfig.Config
		if providerConfig == nil {
			providerConfig = make(map[string]interface{})
		}

		credentials := fileConfig.Credentials
		if credentials == nil {
			credentials = make(map[string]string)
		}

		cfg := &LLMProviderConfig{
			TenantID:     tenantID,
			ProviderName: name,
			DisplayName:  fileConfig.DisplayName,
			Config:       providerConfig,
			Credentials:  credentials,
			Priority:     priority,
			Weight:       weight,
			Enabled:      true,
			HealthStatus: "unknown",
		}

		configs = append(configs, cfg)
	}

	return configs, nil
}

// Reload reloads the configuration file
func (l *YAMLConfigFileLoader) Reload() error {
	return l.reload()
}

// envVarRegex matches ${VAR_NAME} or $VAR_NAME patterns
var envVarRegex = regexp.MustCompile(`\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expandEnvVars expands environment variable references in the string
// Supports both ${VAR_NAME} and $VAR_NAME syntax
// Returns empty string for undefined variables (with a warning)
func expandEnvVars(content string) string {
	return envVarRegex.ReplaceAllStringFunc(content, func(match string) string {
		var varName string
		if strings.HasPrefix(match, "${") {
			varName = match[2 : len(match)-1]
		} else {
			varName = match[1:]
		}

		// Handle default values: ${VAR_NAME:-default}
		defaultVal := ""
		if idx := strings.Index(varName, ":-"); idx != -1 {
			defaultVal = varName[idx+2:]
			varName = varName[:idx]
		}

		if value := os.Getenv(varName); value != "" {
			return value
		}

		if defaultVal != "" {
			return defaultVal
		}

		// Return empty string for undefined variables
		return ""
	})
}

// ValidateConfigFile validates the structure of a config file
func ValidateConfigFile(config *ConfigFile) error {
	if config.Version == "" {
		return fmt.Errorf("config file must specify a version")
	}

	// Validate connectors
	for name, connector := range config.Connectors {
		if connector.Type == "" {
			return fmt.Errorf("connector '%s' must specify a type", name)
		}

		validTypes := map[string]bool{
			"postgres":   true,
			"cassandra":  true,
			"salesforce": true,
			"amadeus":    true,
			"slack":      true,
			"snowflake":  true,
			"custom":     true,
		}

		if !validTypes[connector.Type] {
			return fmt.Errorf("connector '%s' has invalid type '%s'", name, connector.Type)
		}
	}

	// Validate LLM providers
	for name, provider := range config.LLMProviders {
		validProviders := map[string]bool{
			"bedrock":   true,
			"ollama":    true,
			"openai":    true,
			"anthropic": true,
		}

		if !validProviders[name] {
			return fmt.Errorf("invalid LLM provider '%s'", name)
		}

		if provider.Weight < 0 || provider.Weight > 1 {
			return fmt.Errorf("LLM provider '%s' weight must be between 0 and 1", name)
		}
	}

	return nil
}

// GenerateExampleConfigFile generates an example configuration file
func GenerateExampleConfigFile() string {
	return `# AxonFlow Runtime Configuration
# This file configures MCP connectors and LLM providers for Community deployments
# Environment variables can be referenced using ${VAR_NAME} or ${VAR_NAME:-default} syntax

version: "1.0"

connectors:
  # PostgreSQL connector example
  postgres_main:
    type: postgres
    enabled: true
    display_name: "Main Database"
    description: "Primary PostgreSQL database for application data"
    connection_url: ${DATABASE_URL}
    credentials:
      username: ${POSTGRES_USER:-postgres}
      password: ${POSTGRES_PASSWORD}
    options:
      max_open_conns: 25
      max_idle_conns: 5
      conn_max_lifetime: "5m"
    timeout_ms: 30000
    max_retries: 3

  # Salesforce connector example
  salesforce_crm:
    type: salesforce
    enabled: false  # Enable when configured
    display_name: "Salesforce CRM"
    credentials:
      client_id: ${SALESFORCE_CLIENT_ID}
      client_secret: ${SALESFORCE_CLIENT_SECRET}
      username: ${SALESFORCE_USERNAME}
      password: ${SALESFORCE_PASSWORD}
    options:
      instance_url: ${SALESFORCE_INSTANCE_URL:-https://login.salesforce.com}
    timeout_ms: 30000

  # Amadeus travel API example
  amadeus_travel:
    type: amadeus
    enabled: false  # Enable when configured
    display_name: "Amadeus Travel API"
    credentials:
      api_key: ${AMADEUS_API_KEY}
      api_secret: ${AMADEUS_API_SECRET}
    options:
      environment: ${AMADEUS_ENV:-test}
      cache_enabled: true
      cache_ttl: "15m"
    timeout_ms: 30000

llm_providers:
  # Amazon Bedrock (recommended for AWS deployments)
  bedrock:
    enabled: true
    display_name: "Amazon Bedrock"
    config:
      region: ${AWS_REGION:-us-east-1}
      model: ${BEDROCK_MODEL:-anthropic.claude-3-5-sonnet-20240620-v1:0}
    priority: 10
    weight: 0.7

  # Ollama (self-hosted, good for local/private deployments)
  ollama:
    enabled: false  # Enable when running locally
    display_name: "Ollama (Self-hosted)"
    config:
      endpoint: ${OLLAMA_ENDPOINT:-http://localhost:11434}
      model: ${OLLAMA_MODEL:-llama3.1:70b}
    priority: 5
    weight: 0.3

  # OpenAI (alternative commercial provider)
  openai:
    enabled: false  # Enable when API key is available
    display_name: "OpenAI"
    config:
      model: ${OPENAI_MODEL:-gpt-4-turbo}
      max_tokens: 4096
    credentials:
      api_key: ${OPENAI_API_KEY}
    priority: 5
    weight: 0.5

  # Anthropic (direct API access)
  anthropic:
    enabled: false  # Enable when API key is available
    display_name: "Anthropic"
    config:
      model: ${ANTHROPIC_MODEL:-claude-3-5-sonnet-20241022}
      max_tokens: 8192
    credentials:
      api_key: ${ANTHROPIC_API_KEY}
    priority: 5
    weight: 0.5
`
}
