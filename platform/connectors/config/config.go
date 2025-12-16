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
	"strconv"
	"strings"
	"time"

	"axonflow/platform/connectors/base"
)

// LoadFromEnv loads a connector configuration from environment variables
// Environment variables should be prefixed with MCP_<CONNECTOR_NAME>_
// Example: MCP_POSTGRES_URL, MCP_CASSANDRA_USERNAME, etc.
func LoadFromEnv(connectorName, connectorType string) (*base.ConnectorConfig, error) {
	prefix := "MCP_" + connectorName + "_"

	config := &base.ConnectorConfig{
		Name:        connectorName,
		Type:        connectorType,
		Credentials: make(map[string]string),
		Options:     make(map[string]interface{}),
	}

	// Connection URL (required)
	connectionURL := os.Getenv(prefix + "URL")
	if connectionURL == "" {
		return nil, fmt.Errorf("missing required environment variable: %sURL", prefix)
	}
	config.ConnectionURL = connectionURL

	// Tenant ID (optional, defaults to *)
	config.TenantID = getEnvOrDefault(prefix+"TENANT_ID", "*")

	// Timeout (optional, defaults to 5s)
	timeoutStr := os.Getenv(prefix + "TIMEOUT")
	if timeoutStr != "" {
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout format: %s", timeoutStr)
		}
		config.Timeout = timeout
	} else {
		config.Timeout = 5 * time.Second
	}

	// Max retries (optional, defaults to 3)
	maxRetriesStr := os.Getenv(prefix + "MAX_RETRIES")
	if maxRetriesStr != "" {
		maxRetries, err := strconv.Atoi(maxRetriesStr)
		if err != nil {
			return nil, fmt.Errorf("invalid max_retries format: %s", maxRetriesStr)
		}
		config.MaxRetries = maxRetries
	} else {
		config.MaxRetries = 3
	}

	// Credentials (optional)
	if username := os.Getenv(prefix + "USERNAME"); username != "" {
		config.Credentials["username"] = username
	}
	if password := os.Getenv(prefix + "PASSWORD"); password != "" {
		config.Credentials["password"] = password
	}
	if apiKey := os.Getenv(prefix + "API_KEY"); apiKey != "" {
		config.Credentials["api_key"] = apiKey
	}

	return config, nil
}

// LoadPostgresConfig loads PostgreSQL connector configuration
// Defaults to DATABASE_URL if available
func LoadPostgresConfig(connectorName string) (*base.ConnectorConfig, error) {
	// Try MCP-specific env first
	config, err := LoadFromEnv(connectorName, "postgres")
	if err == nil {
		return config, nil
	}

	// Fall back to DATABASE_URL
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return nil, fmt.Errorf("no PostgreSQL configuration found (tried MCP_%s_URL and DATABASE_URL)", connectorName)
	}

	config = &base.ConnectorConfig{
		Name:          connectorName,
		Type:          "postgres",
		ConnectionURL: databaseURL,
		Timeout:       5 * time.Second,
		MaxRetries:    3,
		TenantID:      "*",
		Options: map[string]interface{}{
			"max_open_conns":     25,
			"max_idle_conns":     5,
			"conn_max_lifetime":  "5m",
		},
	}

	return config, nil
}

// LoadCassandraConfig loads Cassandra connector configuration
func LoadCassandraConfig(connectorName string) (*base.ConnectorConfig, error) {
	config, err := LoadFromEnv(connectorName, "cassandra")
	if err != nil {
		return nil, err
	}

	// Cassandra-specific options
	if keyspace := os.Getenv("MCP_" + connectorName + "_KEYSPACE"); keyspace != "" {
		config.Options["keyspace"] = keyspace
	}
	if consistency := os.Getenv("MCP_" + connectorName + "_CONSISTENCY"); consistency != "" {
		config.Options["consistency"] = consistency
	} else {
		config.Options["consistency"] = "QUORUM"
	}

	return config, nil
}

// LoadSlackConfig loads Slack connector configuration
func LoadSlackConfig(connectorName string) (*base.ConnectorConfig, error) {
	prefix := "MCP_" + connectorName + "_"

	// Get bot token from environment
	botToken := os.Getenv(prefix + "BOT_TOKEN")
	if botToken == "" {
		return nil, fmt.Errorf("missing required environment variable: %sBOT_TOKEN", prefix)
	}

	config := &base.ConnectorConfig{
		Name:          connectorName,
		Type:          "slack",
		ConnectionURL: "https://slack.com/api", // Slack uses HTTPS API, not a connection URL
		Credentials: map[string]string{
			"bot_token": botToken,
		},
		Options:    make(map[string]interface{}),
		Timeout:    30 * time.Second, // Slack API can be slower than database queries
		MaxRetries: 3,
		TenantID:   getEnvOrDefault(prefix+"TENANT_ID", "*"),
	}

	// Optional: Custom API URL (for testing or enterprise Slack)
	if baseURL := os.Getenv(prefix + "BASE_URL"); baseURL != "" {
		config.Options["base_url"] = baseURL
	}

	return config, nil
}

// LoadSalesforceConfig loads Salesforce connector configuration
func LoadSalesforceConfig(connectorName string) (*base.ConnectorConfig, error) {
	prefix := "MCP_" + connectorName + "_"

	// Get required credentials
	clientID := os.Getenv(prefix + "CLIENT_ID")
	clientSecret := os.Getenv(prefix + "CLIENT_SECRET")
	username := os.Getenv(prefix + "USERNAME")
	password := os.Getenv(prefix + "PASSWORD")

	if clientID == "" || clientSecret == "" || username == "" || password == "" {
		return nil, fmt.Errorf("missing required Salesforce credentials")
	}

	config := &base.ConnectorConfig{
		Name: connectorName,
		Type: "salesforce",
		Credentials: map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"username":      username,
			"password":      password,
		},
		Options:    make(map[string]interface{}),
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		TenantID:   getEnvOrDefault(prefix+"TENANT_ID", "*"),
	}

	// Optional: Security token
	if securityToken := os.Getenv(prefix + "SECURITY_TOKEN"); securityToken != "" {
		config.Credentials["security_token"] = securityToken
	}

	// Optional: Instance URL
	if instanceURL := os.Getenv(prefix + "INSTANCE_URL"); instanceURL != "" {
		config.Options["instance_url"] = instanceURL
	}

	return config, nil
}

// LoadSnowflakeConfig loads Snowflake connector configuration
func LoadSnowflakeConfig(connectorName string) (*base.ConnectorConfig, error) {
	prefix := "MCP_" + connectorName + "_"

	// Get required credentials
	account := os.Getenv(prefix + "ACCOUNT")
	username := os.Getenv(prefix + "USERNAME")
	password := os.Getenv(prefix + "PASSWORD")
	privateKeyPath := os.Getenv(prefix + "PRIVATE_KEY_PATH")
	privateKey := os.Getenv(prefix + "PRIVATE_KEY")

	// Account and username are always required
	if account == "" || username == "" {
		return nil, fmt.Errorf("missing required Snowflake credentials (account, username)")
	}

	// Either password OR private key must be provided (not both required)
	if password == "" && privateKeyPath == "" && privateKey == "" {
		return nil, fmt.Errorf("missing authentication: provide either PASSWORD or PRIVATE_KEY_PATH or PRIVATE_KEY")
	}

	credentials := map[string]string{
		"account":  account,
		"username": username,
	}

	// Add authentication method
	if password != "" {
		credentials["password"] = password
	}
	if privateKeyPath != "" {
		credentials["private_key_path"] = privateKeyPath
	}
	if privateKey != "" {
		credentials["private_key"] = privateKey
	}

	config := &base.ConnectorConfig{
		Name:       connectorName,
		Type:       "snowflake",
		Credentials: credentials,
		Options:    make(map[string]interface{}),
		Timeout:    60 * time.Second, // Snowflake queries can be slow
		MaxRetries: 3,
		TenantID:   getEnvOrDefault(prefix+"TENANT_ID", "*"),
	}

	// Optional: Database, schema, warehouse, role
	if database := os.Getenv(prefix + "DATABASE"); database != "" {
		config.Credentials["database"] = database
	}
	if schema := os.Getenv(prefix + "SCHEMA"); schema != "" {
		config.Credentials["schema"] = schema
	}
	if warehouse := os.Getenv(prefix + "WAREHOUSE"); warehouse != "" {
		config.Credentials["warehouse"] = warehouse
	}
	if role := os.Getenv(prefix + "ROLE"); role != "" {
		config.Credentials["role"] = role
	}

	// Connection pool options
	if maxConns := os.Getenv(prefix + "MAX_OPEN_CONNS"); maxConns != "" {
		if val, err := strconv.Atoi(maxConns); err == nil {
			config.Options["max_open_conns"] = val
		}
	}

	return config, nil
}

// getEnvOrDefault returns environment variable value or default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// LoadAmadeusConfig loads Amadeus connector configuration
func LoadAmadeusConfig(connectorName string) (*base.ConnectorConfig, error) {
	prefix := "MCP_" + connectorName + "_"

	// Determine which environment to use (test or production)
	environment := getEnvOrDefault(prefix+"ENVIRONMENT", "")
	if environment == "" {
		environment = getEnvOrDefault("AMADEUS_ENV", "test")
	}

	// Normalize environment to lowercase
	environment = strings.ToLower(strings.TrimSpace(environment))
	if environment != "test" && environment != "production" {
		environment = "test" // Default to test if invalid value
	}

	// Load credentials based on environment
	var apiKey, apiSecret, baseURL string

	if environment == "production" {
		// Production credentials
		apiKey = os.Getenv("AMADEUS_API_KEY_PROD")
		apiSecret = os.Getenv("AMADEUS_API_SECRET_PROD")
		baseURL = os.Getenv("AMADEUS_URL_PROD")

		// Fallback to prefixed versions
		if apiKey == "" {
			apiKey = os.Getenv(prefix + "API_KEY_PROD")
		}
		if apiSecret == "" {
			apiSecret = os.Getenv(prefix + "API_SECRET_PROD")
		}
		if baseURL == "" {
			baseURL = os.Getenv(prefix + "URL_PROD")
		}

		// Default production URL
		if baseURL == "" {
			baseURL = "https://api.amadeus.com"
		}
	} else {
		// Test credentials
		apiKey = os.Getenv("AMADEUS_API_KEY_TEST")
		apiSecret = os.Getenv("AMADEUS_API_SECRET_TEST")
		baseURL = os.Getenv("AMADEUS_URL_TEST")

		// Fallback to prefixed versions
		if apiKey == "" {
			apiKey = os.Getenv(prefix + "API_KEY_TEST")
		}
		if apiSecret == "" {
			apiSecret = os.Getenv(prefix + "API_SECRET_TEST")
		}
		if baseURL == "" {
			baseURL = os.Getenv(prefix + "URL_TEST")
		}

		// Fallback to generic (non-suffixed) credentials
		// This supports CloudFormation deployments that use AMADEUS_API_KEY/AMADEUS_API_SECRET
		if apiKey == "" {
			apiKey = os.Getenv("AMADEUS_API_KEY")
		}
		if apiSecret == "" {
			apiSecret = os.Getenv("AMADEUS_API_SECRET")
		}
		if apiKey == "" {
			apiKey = os.Getenv(prefix + "API_KEY")
		}
		if apiSecret == "" {
			apiSecret = os.Getenv(prefix + "API_SECRET")
		}

		// Default test URL
		if baseURL == "" {
			baseURL = "https://test.api.amadeus.com"
		}
	}

	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("missing required Amadeus credentials for %s environment (API_KEY_%s, API_SECRET_%s)",
			environment, strings.ToUpper(environment), strings.ToUpper(environment))
	}

	config := &base.ConnectorConfig{
		Name:          connectorName,
		Type:          "amadeus",
		ConnectionURL: baseURL,
		Credentials: map[string]string{
			"api_key":    apiKey,
			"api_secret": apiSecret,
		},
		Options: map[string]interface{}{
			"environment":   environment,
			"base_url":      baseURL,
			"cache_enabled": true,
			"cache_ttl":     "15m",
		},
		Timeout:    30 * time.Second, // Amadeus API calls can take time
		MaxRetries: 3,
		TenantID:   getEnvOrDefault(prefix+"TENANT_ID", "*"),
	}

	return config, nil
}

// ValidateConfig validates a connector configuration
func ValidateConfig(config *base.ConnectorConfig) error {
	if config.Name == "" {
		return fmt.Errorf("connector name is required")
	}
	if config.Type == "" {
		return fmt.Errorf("connector type is required")
	}
	// Note: ConnectionURL not required for API-based connectors like Amadeus
	if config.Type != "amadeus" && config.Type != "slack" && config.Type != "salesforce" {
		if config.ConnectionURL == "" {
			return fmt.Errorf("connection URL is required for %s connector", config.Type)
		}
	}
	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if config.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}
	return nil
}
