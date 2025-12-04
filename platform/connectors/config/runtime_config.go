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

package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"axonflow/platform/connectors/base"
)

// SecretsManager provides an interface for retrieving secrets
// This allows for different implementations (AWS Secrets Manager, local file, etc.)
type SecretsManager interface {
	GetSecret(ctx context.Context, secretARN string) (map[string]string, error)
}

// LLMProviderConfig represents configuration for an LLM provider
type LLMProviderConfig struct {
	ID                    string                 `json:"id"`
	TenantID              string                 `json:"tenant_id"`
	ProviderName          string                 `json:"provider_name"`
	DisplayName           string                 `json:"display_name,omitempty"`
	Config                map[string]interface{} `json:"config"`
	CredentialsSecretARN  string                 `json:"credentials_secret_arn,omitempty"`
	Credentials           map[string]string      `json:"-"` // Populated at runtime, never serialized
	Priority              int                    `json:"priority"`
	Weight                float64                `json:"weight"`
	Enabled               bool                   `json:"enabled"`
	HealthStatus          string                 `json:"health_status"`
	CostPer1kInputTokens  float64                `json:"cost_per_1k_input_tokens,omitempty"`
	CostPer1kOutputTokens float64                `json:"cost_per_1k_output_tokens,omitempty"`
}

// ConnectorConfigDB represents a connector config as stored in the database
type ConnectorConfigDB struct {
	ID                       string                 `json:"id"`
	TenantID                 string                 `json:"tenant_id"`
	ConnectorName            string                 `json:"connector_name"`
	ConnectorType            string                 `json:"connector_type"`
	DisplayName              string                 `json:"display_name,omitempty"`
	Description              string                 `json:"description,omitempty"`
	ConnectionURL            string                 `json:"connection_url,omitempty"`
	Options                  map[string]interface{} `json:"options"`
	CredentialsSecretARN     string                 `json:"credentials_secret_arn,omitempty"`
	CredentialsSecretVersion string                 `json:"credentials_secret_version,omitempty"`
	TimeoutMs                int                    `json:"timeout_ms"`
	MaxRetries               int                    `json:"max_retries"`
	Enabled                  bool                   `json:"enabled"`
	HealthStatus             string                 `json:"health_status"`
	BlockedOperations        []string               `json:"blocked_operations,omitempty"`
}

// ConfigSource indicates where a configuration was loaded from
type ConfigSource string

const (
	ConfigSourceDatabase ConfigSource = "database"
	ConfigSourceFile     ConfigSource = "config_file"
	ConfigSourceEnvVars  ConfigSource = "env_vars"
)

// RuntimeConfigService manages runtime configuration loading with caching
// Implements three-tier configuration priority: Database > Config File > Env Vars
type RuntimeConfigService struct {
	db             *sql.DB
	cache          *ConfigCache
	secretsManager SecretsManager
	logger         *log.Logger
	mu             sync.RWMutex

	// Configuration sources (in priority order)
	configFile string // Path to YAML/JSON config file (OSS mode)
	selfHosted bool   // If true, prefer config file over database

	// Config file loader (set by SetConfigFileLoader)
	fileLoader ConfigFileLoader
}

// ConfigFileLoader interface for loading configs from files
type ConfigFileLoader interface {
	LoadConnectors(tenantID string) ([]*base.ConnectorConfig, error)
	LoadLLMProviders(tenantID string) ([]*LLMProviderConfig, error)
}

// RuntimeConfigServiceOptions holds options for creating a RuntimeConfigService
type RuntimeConfigServiceOptions struct {
	DB             *sql.DB
	SecretsManager SecretsManager
	ConfigFile     string
	SelfHosted     bool
	CacheTTL       time.Duration
	Logger         *log.Logger
}

// NewRuntimeConfigService creates a new RuntimeConfigService
func NewRuntimeConfigService(opts RuntimeConfigServiceOptions) *RuntimeConfigService {
	logger := opts.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[RUNTIME_CONFIG] ", log.LstdFlags)
	}

	cacheTTL := opts.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}

	svc := &RuntimeConfigService{
		db:             opts.DB,
		cache:          NewConfigCache(cacheTTL),
		secretsManager: opts.SecretsManager,
		configFile:     opts.ConfigFile,
		selfHosted:     opts.SelfHosted,
		logger:         logger,
	}

	return svc
}

// SetConfigFileLoader sets the config file loader for OSS mode
func (s *RuntimeConfigService) SetConfigFileLoader(loader ConfigFileLoader) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileLoader = loader
}

// GetConnectorConfigs returns all enabled connector configs for a tenant
// Priority: 1. Database (Enterprise) 2. Config file (OSS) 3. Env vars (Fallback)
func (s *RuntimeConfigService) GetConnectorConfigs(ctx context.Context, tenantID string) ([]*base.ConnectorConfig, ConfigSource, error) {
	// Check cache first
	if cached, ok := s.cache.GetConnectors(tenantID); ok {
		s.logger.Printf("Cache hit for connector configs (tenant: %s)", tenantID)
		return cached, ConfigSourceDatabase, nil // Note: source might be different but cache hit
	}

	s.logger.Printf("Cache miss for connector configs (tenant: %s), loading from sources", tenantID)

	// Priority 1: Database (for Enterprise)
	if s.db != nil && !s.selfHosted {
		configs, err := s.loadConnectorsFromDatabase(ctx, tenantID)
		if err == nil && len(configs) > 0 {
			s.cache.SetConnectors(tenantID, configs)
			s.logger.Printf("Loaded %d connector configs from database for tenant %s", len(configs), tenantID)
			return configs, ConfigSourceDatabase, nil
		}
		if err != nil {
			s.logger.Printf("Failed to load from database (tenant: %s): %v", tenantID, err)
		}
	}

	// Priority 2: Config file (for OSS)
	s.mu.RLock()
	fileLoader := s.fileLoader
	s.mu.RUnlock()

	if fileLoader != nil {
		configs, err := fileLoader.LoadConnectors(tenantID)
		if err == nil && len(configs) > 0 {
			s.cache.SetConnectors(tenantID, configs)
			s.logger.Printf("Loaded %d connector configs from config file for tenant %s", len(configs), tenantID)
			return configs, ConfigSourceFile, nil
		}
		if err != nil {
			s.logger.Printf("Failed to load from config file (tenant: %s): %v", tenantID, err)
		}
	}

	// Priority 3: Environment variables (fallback)
	configs := s.loadConnectorsFromEnvVars()
	if len(configs) > 0 {
		s.cache.SetConnectors(tenantID, configs)
		s.logger.Printf("Loaded %d connector configs from environment variables", len(configs))
		return configs, ConfigSourceEnvVars, nil
	}

	return nil, "", fmt.Errorf("no connector configurations found for tenant %s", tenantID)
}

// GetConnectorConfig returns a specific connector config by name
func (s *RuntimeConfigService) GetConnectorConfig(ctx context.Context, tenantID, connectorName string) (*base.ConnectorConfig, ConfigSource, error) {
	configs, source, err := s.GetConnectorConfigs(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}

	for _, cfg := range configs {
		if cfg.Name == connectorName {
			return cfg, source, nil
		}
	}

	return nil, "", fmt.Errorf("connector '%s' not found for tenant %s", connectorName, tenantID)
}

// GetLLMProviderConfigs returns all enabled LLM provider configs for a tenant
func (s *RuntimeConfigService) GetLLMProviderConfigs(ctx context.Context, tenantID string) ([]*LLMProviderConfig, ConfigSource, error) {
	// Check cache first
	if cached, ok := s.cache.GetLLMProviders(tenantID); ok {
		s.logger.Printf("Cache hit for LLM provider configs (tenant: %s)", tenantID)
		return cached, ConfigSourceDatabase, nil
	}

	s.logger.Printf("Cache miss for LLM provider configs (tenant: %s), loading from sources", tenantID)

	// Priority 1: Database (for Enterprise)
	if s.db != nil && !s.selfHosted {
		configs, err := s.loadLLMProvidersFromDatabase(ctx, tenantID)
		if err == nil && len(configs) > 0 {
			s.cache.SetLLMProviders(tenantID, configs)
			s.logger.Printf("Loaded %d LLM provider configs from database for tenant %s", len(configs), tenantID)
			return configs, ConfigSourceDatabase, nil
		}
		if err != nil {
			s.logger.Printf("Failed to load LLM providers from database (tenant: %s): %v", tenantID, err)
		}
	}

	// Priority 2: Config file (for OSS)
	s.mu.RLock()
	fileLoader := s.fileLoader
	s.mu.RUnlock()

	if fileLoader != nil {
		configs, err := fileLoader.LoadLLMProviders(tenantID)
		if err == nil && len(configs) > 0 {
			s.cache.SetLLMProviders(tenantID, configs)
			s.logger.Printf("Loaded %d LLM provider configs from config file for tenant %s", len(configs), tenantID)
			return configs, ConfigSourceFile, nil
		}
		if err != nil {
			s.logger.Printf("Failed to load LLM providers from config file (tenant: %s): %v", tenantID, err)
		}
	}

	// Priority 3: Environment variables (fallback)
	configs := s.loadLLMProvidersFromEnvVars()
	if len(configs) > 0 {
		s.cache.SetLLMProviders(tenantID, configs)
		s.logger.Printf("Loaded %d LLM provider configs from environment variables", len(configs))
		return configs, ConfigSourceEnvVars, nil
	}

	return nil, "", fmt.Errorf("no LLM provider configurations found for tenant %s", tenantID)
}

// RefreshConnectorConfig invalidates cache and reloads a connector's configuration
func (s *RuntimeConfigService) RefreshConnectorConfig(ctx context.Context, tenantID, connectorName string) error {
	s.cache.InvalidateConnector(tenantID, connectorName)
	s.logger.Printf("Invalidated cache for connector %s (tenant: %s)", connectorName, tenantID)
	return nil
}

// RefreshLLMProviderConfig invalidates cache and reloads an LLM provider's configuration
func (s *RuntimeConfigService) RefreshLLMProviderConfig(ctx context.Context, tenantID, providerName string) error {
	s.cache.InvalidateLLMProvider(tenantID, providerName)
	s.logger.Printf("Invalidated cache for LLM provider %s (tenant: %s)", providerName, tenantID)
	return nil
}

// RefreshAllConfigs invalidates all cached configurations
func (s *RuntimeConfigService) RefreshAllConfigs() {
	s.cache.InvalidateAll()
	s.logger.Println("Invalidated all cached configurations")
}

// GetCacheStats returns cache performance statistics
func (s *RuntimeConfigService) GetCacheStats() CacheStats {
	return s.cache.GetStats()
}

// GetCacheHitRate returns the cache hit rate percentage
func (s *RuntimeConfigService) GetCacheHitRate() float64 {
	return s.cache.HitRate()
}

// loadConnectorsFromDatabase loads connector configs from the database
func (s *RuntimeConfigService) loadConnectorsFromDatabase(ctx context.Context, tenantID string) ([]*base.ConnectorConfig, error) {
	query := `
		SELECT
			cc.id,
			cc.tenant_id,
			cc.connector_name,
			cc.connector_type,
			cc.display_name,
			cc.description,
			cc.connection_url,
			cc.options,
			cc.credentials_secret_arn,
			cc.credentials_secret_version,
			cc.timeout_ms,
			cc.max_retries,
			cc.enabled,
			cc.health_status,
			COALESCE(
				cdo_tenant.blocked_operations,
				cdo_global.blocked_operations,
				ARRAY[]::TEXT[]
			) as blocked_operations
		FROM connector_configs cc
		LEFT JOIN connector_dangerous_operations cdo_tenant
			ON cc.connector_type = cdo_tenant.connector_type
			AND cc.tenant_id = cdo_tenant.tenant_id
		LEFT JOIN connector_dangerous_operations cdo_global
			ON cc.connector_type = cdo_global.connector_type
			AND cdo_global.tenant_id IS NULL
		WHERE cc.tenant_id = $1 AND cc.enabled = true
		ORDER BY cc.connector_name
	`

	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var configs []*base.ConnectorConfig
	for rows.Next() {
		var dbConfig ConnectorConfigDB
		var optionsJSON []byte
		var blockedOps []string

		err := rows.Scan(
			&dbConfig.ID,
			&dbConfig.TenantID,
			&dbConfig.ConnectorName,
			&dbConfig.ConnectorType,
			&dbConfig.DisplayName,
			&dbConfig.Description,
			&dbConfig.ConnectionURL,
			&optionsJSON,
			&dbConfig.CredentialsSecretARN,
			&dbConfig.CredentialsSecretVersion,
			&dbConfig.TimeoutMs,
			&dbConfig.MaxRetries,
			&dbConfig.Enabled,
			&dbConfig.HealthStatus,
			&blockedOps,
		)
		if err != nil {
			s.logger.Printf("Error scanning connector config: %v", err)
			continue
		}

		// Parse options JSON
		if len(optionsJSON) > 0 {
			if err := json.Unmarshal(optionsJSON, &dbConfig.Options); err != nil {
				s.logger.Printf("Error parsing options for %s: %v", dbConfig.ConnectorName, err)
				dbConfig.Options = make(map[string]interface{})
			}
		} else {
			dbConfig.Options = make(map[string]interface{})
		}

		dbConfig.BlockedOperations = blockedOps

		// Convert to base.ConnectorConfig
		cfg := s.dbConfigToBaseConfig(&dbConfig)

		// Load credentials from Secrets Manager if configured
		if dbConfig.CredentialsSecretARN != "" && s.secretsManager != nil {
			creds, err := s.secretsManager.GetSecret(ctx, dbConfig.CredentialsSecretARN)
			if err != nil {
				s.logger.Printf("Failed to load credentials for %s: %v", dbConfig.ConnectorName, err)
			} else {
				cfg.Credentials = creds
			}
		}

		configs = append(configs, cfg)
	}

	return configs, rows.Err()
}

// loadLLMProvidersFromDatabase loads LLM provider configs from the database
func (s *RuntimeConfigService) loadLLMProvidersFromDatabase(ctx context.Context, tenantID string) ([]*LLMProviderConfig, error) {
	query := `
		SELECT
			id,
			tenant_id,
			provider_name,
			display_name,
			config,
			credentials_secret_arn,
			priority,
			weight,
			enabled,
			health_status,
			cost_per_1k_input_tokens,
			cost_per_1k_output_tokens
		FROM llm_provider_configs
		WHERE tenant_id = $1 AND enabled = true
		ORDER BY priority DESC, weight DESC
	`

	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var configs []*LLMProviderConfig
	for rows.Next() {
		var cfg LLMProviderConfig
		var configJSON []byte
		var displayName, secretARN sql.NullString
		var costInput, costOutput sql.NullFloat64

		err := rows.Scan(
			&cfg.ID,
			&cfg.TenantID,
			&cfg.ProviderName,
			&displayName,
			&configJSON,
			&secretARN,
			&cfg.Priority,
			&cfg.Weight,
			&cfg.Enabled,
			&cfg.HealthStatus,
			&costInput,
			&costOutput,
		)
		if err != nil {
			s.logger.Printf("Error scanning LLM provider config: %v", err)
			continue
		}

		if displayName.Valid {
			cfg.DisplayName = displayName.String
		}
		if secretARN.Valid {
			cfg.CredentialsSecretARN = secretARN.String
		}
		if costInput.Valid {
			cfg.CostPer1kInputTokens = costInput.Float64
		}
		if costOutput.Valid {
			cfg.CostPer1kOutputTokens = costOutput.Float64
		}

		// Parse config JSON
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg.Config); err != nil {
				s.logger.Printf("Error parsing config for %s: %v", cfg.ProviderName, err)
				cfg.Config = make(map[string]interface{})
			}
		} else {
			cfg.Config = make(map[string]interface{})
		}

		// Load credentials from Secrets Manager if configured
		if cfg.CredentialsSecretARN != "" && s.secretsManager != nil {
			creds, err := s.secretsManager.GetSecret(ctx, cfg.CredentialsSecretARN)
			if err != nil {
				s.logger.Printf("Failed to load credentials for LLM provider %s: %v", cfg.ProviderName, err)
			} else {
				cfg.Credentials = creds
			}
		}

		configs = append(configs, &cfg)
	}

	return configs, rows.Err()
}

// loadConnectorsFromEnvVars loads connector configs from environment variables
// This provides backward compatibility with existing deployments
func (s *RuntimeConfigService) loadConnectorsFromEnvVars() []*base.ConnectorConfig {
	var configs []*base.ConnectorConfig

	// Try to load each known connector type from env vars
	connectorLoaders := map[string]func(string) (*base.ConnectorConfig, error){
		"postgres":   LoadPostgresConfig,
		"cassandra":  LoadCassandraConfig,
		"salesforce": LoadSalesforceConfig,
		"slack":      LoadSlackConfig,
		"snowflake":  LoadSnowflakeConfig,
		"amadeus":    LoadAmadeusConfig,
	}

	// Check for connectors defined via MCP_ prefix pattern
	for connType, loader := range connectorLoaders {
		cfg, err := loader(connType)
		if err == nil && cfg != nil {
			configs = append(configs, cfg)
			s.logger.Printf("Loaded %s connector from environment variables", connType)
		}
	}

	return configs
}

// loadLLMProvidersFromEnvVars loads LLM provider configs from environment variables
func (s *RuntimeConfigService) loadLLMProvidersFromEnvVars() []*LLMProviderConfig {
	var configs []*LLMProviderConfig

	// Bedrock configuration
	if region := os.Getenv("BEDROCK_REGION"); region != "" {
		model := os.Getenv("BEDROCK_MODEL")
		if model == "" {
			model = "anthropic.claude-3-5-sonnet-20240620-v1:0"
		}
		configs = append(configs, &LLMProviderConfig{
			ProviderName: "bedrock",
			DisplayName:  "Amazon Bedrock",
			Config: map[string]interface{}{
				"region": region,
				"model":  model,
			},
			Priority: 10,
			Weight:   1.0,
			Enabled:  true,
		})
		s.logger.Println("Loaded Bedrock config from environment variables")
	}

	// Ollama configuration
	if endpoint := os.Getenv("OLLAMA_ENDPOINT"); endpoint != "" {
		model := os.Getenv("OLLAMA_MODEL")
		if model == "" {
			model = "llama3.1:70b"
		}
		configs = append(configs, &LLMProviderConfig{
			ProviderName: "ollama",
			DisplayName:  "Ollama (Self-hosted)",
			Config: map[string]interface{}{
				"endpoint": endpoint,
				"model":    model,
			},
			Priority: 5,
			Weight:   1.0,
			Enabled:  true,
		})
		s.logger.Println("Loaded Ollama config from environment variables")
	}

	// OpenAI configuration
	if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
		model := os.Getenv("OPENAI_MODEL")
		if model == "" {
			model = "gpt-4-turbo"
		}
		configs = append(configs, &LLMProviderConfig{
			ProviderName: "openai",
			DisplayName:  "OpenAI",
			Config: map[string]interface{}{
				"model": model,
			},
			Credentials: map[string]string{
				"api_key": apiKey,
			},
			Priority: 5,
			Weight:   1.0,
			Enabled:  true,
		})
		s.logger.Println("Loaded OpenAI config from environment variables")
	}

	// Anthropic configuration
	if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
		model := os.Getenv("ANTHROPIC_MODEL")
		if model == "" {
			model = "claude-3-5-sonnet-20241022"
		}
		configs = append(configs, &LLMProviderConfig{
			ProviderName: "anthropic",
			DisplayName:  "Anthropic",
			Config: map[string]interface{}{
				"model": model,
			},
			Credentials: map[string]string{
				"api_key": apiKey,
			},
			Priority: 5,
			Weight:   1.0,
			Enabled:  true,
		})
		s.logger.Println("Loaded Anthropic config from environment variables")
	}

	return configs
}

// dbConfigToBaseConfig converts a database config to base.ConnectorConfig
func (s *RuntimeConfigService) dbConfigToBaseConfig(dbConfig *ConnectorConfigDB) *base.ConnectorConfig {
	cfg := &base.ConnectorConfig{
		Name:          dbConfig.ConnectorName,
		Type:          dbConfig.ConnectorType,
		ConnectionURL: dbConfig.ConnectionURL,
		Credentials:   make(map[string]string),
		Options:       dbConfig.Options,
		Timeout:       time.Duration(dbConfig.TimeoutMs) * time.Millisecond,
		MaxRetries:    dbConfig.MaxRetries,
		TenantID:      dbConfig.TenantID,
	}

	// Store blocked operations in options for access by connectors
	if len(dbConfig.BlockedOperations) > 0 {
		cfg.Options["blocked_operations"] = dbConfig.BlockedOperations
	}

	return cfg
}

// StartPeriodicCleanup starts a background goroutine that cleans up expired cache entries
func (s *RuntimeConfigService) StartPeriodicCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.logger.Println("Stopping periodic cache cleanup")
				return
			case <-ticker.C:
				evicted := s.cache.Cleanup()
				if evicted > 0 {
					s.logger.Printf("Cleaned up %d expired cache entries", evicted)
				}
			}
		}
	}()
}
