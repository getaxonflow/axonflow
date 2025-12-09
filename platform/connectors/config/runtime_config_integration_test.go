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
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"

	_ "github.com/lib/pq"
)

// Integration tests for RuntimeConfigService with real PostgreSQL
// These tests require DATABASE_URL to be set and migration 007 to be applied

func getTestDB(t *testing.T) *sql.DB {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return db
}

func setupTestTenant(t *testing.T, db *sql.DB, tenantID string) func() {
	// Ensure test tenant exists
	_, err := db.Exec(`
		INSERT INTO customers (organization_id, tenant_id, name, status)
		VALUES ($1, $2, $3, 'active')
		ON CONFLICT (organization_id) DO UPDATE SET tenant_id = $2, status = 'active'
	`, tenantID, tenantID, "Test Tenant "+tenantID)
	if err != nil {
		t.Fatalf("Failed to create test tenant: %v", err)
	}

	// Return cleanup function
	return func() {
		// Clean up test data in order (respecting foreign keys)
		_, _ = db.Exec("DELETE FROM config_audit_log WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec("DELETE FROM connector_configs WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec("DELETE FROM llm_provider_configs WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec("DELETE FROM connector_dangerous_operations WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec("DELETE FROM customers WHERE tenant_id = $1", tenantID)
	}
}

// TestRuntimeConfigService_GetConnectorConfigs_FromDatabase tests loading connector configs from DB
func TestRuntimeConfigService_GetConnectorConfigs_FromDatabase(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenantID := "test_tenant_connector_" + time.Now().Format("20060102150405")
	cleanup := setupTestTenant(t, db, tenantID)
	defer cleanup()

	// Insert test connector config
	_, err := db.Exec(`
		INSERT INTO connector_configs (tenant_id, connector_name, connector_type, connection_url, options, timeout_ms, max_retries, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, tenantID, "test_postgres", "postgres", "postgres://localhost:5432/testdb",
		`{"schema": "public", "ssl_mode": "require"}`, 30000, 3, true)
	if err != nil {
		t.Fatalf("Failed to insert test connector: %v", err)
	}

	// Create RuntimeConfigService with database
	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 100 * time.Millisecond,
	})

	ctx := context.Background()
	configs, source, err := svc.GetConnectorConfigs(ctx, tenantID)

	if err != nil {
		t.Fatalf("GetConnectorConfigs failed: %v", err)
	}

	if source != ConfigSourceDatabase {
		t.Errorf("Expected source %s, got %s", ConfigSourceDatabase, source)
	}

	if len(configs) != 1 {
		t.Fatalf("Expected 1 config, got %d", len(configs))
	}

	cfg := configs[0]
	if cfg.Name != "test_postgres" {
		t.Errorf("Expected connector name 'test_postgres', got '%s'", cfg.Name)
	}
	if cfg.Type != "postgres" {
		t.Errorf("Expected connector type 'postgres', got '%s'", cfg.Type)
	}
	if cfg.ConnectionURL != "postgres://localhost:5432/testdb" {
		t.Errorf("Unexpected connection URL: %s", cfg.ConnectionURL)
	}
}

// TestRuntimeConfigService_GetLLMProviders_FromDatabase tests loading LLM providers from DB
func TestRuntimeConfigService_GetLLMProviders_FromDatabase(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenantID := "test_tenant_llm_" + time.Now().Format("20060102150405")
	cleanup := setupTestTenant(t, db, tenantID)
	defer cleanup()

	// Insert test LLM provider configs
	_, err := db.Exec(`
		INSERT INTO llm_provider_configs (tenant_id, provider_name, display_name, config, priority, weight, enabled)
		VALUES
			($1, 'bedrock', 'Amazon Bedrock', '{"region": "us-east-1", "model": "anthropic.claude-3-sonnet"}', 10, 0.70, true),
			($1, 'openai', 'OpenAI', '{"model": "gpt-4-turbo"}', 5, 0.30, true),
			($1, 'ollama', 'Ollama (disabled)', '{"endpoint": "http://ollama:11434"}', 1, 0.50, false)
	`, tenantID)
	if err != nil {
		t.Fatalf("Failed to insert test LLM providers: %v", err)
	}

	// Create RuntimeConfigService with database
	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 100 * time.Millisecond,
	})

	ctx := context.Background()
	configs, source, err := svc.GetLLMProviderConfigs(ctx, tenantID)

	if err != nil {
		t.Fatalf("GetLLMProviderConfigs failed: %v", err)
	}

	if source != ConfigSourceDatabase {
		t.Errorf("Expected source %s, got %s", ConfigSourceDatabase, source)
	}

	// Should only return enabled providers (2)
	if len(configs) != 2 {
		t.Fatalf("Expected 2 enabled configs, got %d", len(configs))
	}

	// Verify ordering by priority (bedrock first with priority 10)
	if configs[0].ProviderName != "bedrock" {
		t.Errorf("Expected first provider to be 'bedrock' (highest priority), got '%s'", configs[0].ProviderName)
	}

	if configs[1].ProviderName != "openai" {
		t.Errorf("Expected second provider to be 'openai', got '%s'", configs[1].ProviderName)
	}
}

// TestRuntimeConfigService_ThreeTierPriority tests DB > File > Env priority
func TestRuntimeConfigService_ThreeTierPriority(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenantID := "test_tenant_priority_" + time.Now().Format("20060102150405")
	cleanup := setupTestTenant(t, db, tenantID)
	defer cleanup()

	// Set up environment variable
	os.Setenv("DATABASE_URL", "postgres://envvar:5432/envdb")
	defer os.Unsetenv("DATABASE_URL")

	// Set up mock file loader (simulates config file)
	mockLoader := &mockConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "file_postgres", Type: "postgres", ConnectionURL: "postgres://file:5432/filedb", TenantID: "*"},
		},
	}

	// Test 1: No DB config → should use file config
	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 100 * time.Millisecond,
	})
	svc.SetConfigFileLoader(mockLoader)

	ctx := context.Background()
	configs, source, err := svc.GetConnectorConfigs(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetConnectorConfigs failed: %v", err)
	}

	// No DB config for this tenant, should fall back to file
	if source != ConfigSourceFile {
		t.Errorf("Test 1: Expected source %s (no DB config), got %s", ConfigSourceFile, source)
	}

	// Test 2: Add DB config → should use DB config (higher priority)
	_, err = db.Exec(`
		INSERT INTO connector_configs (tenant_id, connector_name, connector_type, connection_url, enabled)
		VALUES ($1, 'db_postgres', 'postgres', 'postgres://db:5432/dbconfig', true)
	`, tenantID)
	if err != nil {
		t.Fatalf("Failed to insert DB config: %v", err)
	}

	// Clear cache
	err = svc.RefreshConnectorConfig(ctx, tenantID, "")
	if err != nil {
		t.Fatalf("Failed to refresh cache: %v", err)
	}

	configs, source, err = svc.GetConnectorConfigs(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetConnectorConfigs after DB insert failed: %v", err)
	}

	if source != ConfigSourceDatabase {
		t.Errorf("Test 2: Expected source %s (DB has config), got %s", ConfigSourceDatabase, source)
	}

	// Verify we got DB config, not file config
	foundDBConfig := false
	for _, cfg := range configs {
		if cfg.Name == "db_postgres" && cfg.ConnectionURL == "postgres://db:5432/dbconfig" {
			foundDBConfig = true
		}
	}
	if !foundDBConfig {
		t.Error("Test 2: Expected to find 'db_postgres' from database")
	}
}

// TestRuntimeConfigService_CacheWithDatabase tests cache behavior with real database
func TestRuntimeConfigService_CacheWithDatabase(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenantID := "test_tenant_cache_" + time.Now().Format("20060102150405")
	cleanup := setupTestTenant(t, db, tenantID)
	defer cleanup()

	// Insert initial config
	_, err := db.Exec(`
		INSERT INTO connector_configs (tenant_id, connector_name, connector_type, connection_url, enabled)
		VALUES ($1, 'cache_test', 'postgres', 'postgres://original:5432/db', true)
	`, tenantID)
	if err != nil {
		t.Fatalf("Failed to insert initial config: %v", err)
	}

	// Create service with short TTL
	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 200 * time.Millisecond,
	})

	ctx := context.Background()

	// First call - cache miss
	configs, _, err := svc.GetConnectorConfigs(ctx, tenantID)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}
	if configs[0].ConnectionURL != "postgres://original:5432/db" {
		t.Error("First call: unexpected connection URL")
	}

	// Update DB directly
	_, err = db.Exec(`
		UPDATE connector_configs SET connection_url = 'postgres://updated:5432/db' WHERE tenant_id = $1
	`, tenantID)
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}

	// Second call - should hit cache (return old data)
	configs, _, err = svc.GetConnectorConfigs(ctx, tenantID)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}
	if configs[0].ConnectionURL != "postgres://original:5432/db" {
		t.Error("Second call: expected cached (original) data")
	}

	// Wait for cache to expire
	time.Sleep(250 * time.Millisecond)

	// Third call - cache expired, should get updated data
	configs, _, err = svc.GetConnectorConfigs(ctx, tenantID)
	if err != nil {
		t.Fatalf("Third call failed: %v", err)
	}
	if configs[0].ConnectionURL != "postgres://updated:5432/db" {
		t.Error("Third call: expected updated data after cache expiry")
	}

	// Verify cache hit rate
	hitRate := svc.GetCacheHitRate()
	// 1 miss, 1 hit, 1 miss = 33.33%
	if hitRate < 30.0 || hitRate > 40.0 {
		t.Errorf("Expected ~33%% hit rate, got %.2f%%", hitRate)
	}
}

// TestRuntimeConfigService_RefreshCache tests manual cache refresh
func TestRuntimeConfigService_RefreshCache(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenantID := "test_tenant_refresh_" + time.Now().Format("20060102150405")
	cleanup := setupTestTenant(t, db, tenantID)
	defer cleanup()

	// Insert initial config
	_, err := db.Exec(`
		INSERT INTO connector_configs (tenant_id, connector_name, connector_type, connection_url, enabled)
		VALUES ($1, 'refresh_test', 'postgres', 'postgres://before:5432/db', true)
	`, tenantID)
	if err != nil {
		t.Fatalf("Failed to insert initial config: %v", err)
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 1 * time.Minute, // Long TTL
	})

	ctx := context.Background()

	// First call - populates cache
	configs, _, _ := svc.GetConnectorConfigs(ctx, tenantID)
	if configs[0].ConnectionURL != "postgres://before:5432/db" {
		t.Error("First call: unexpected initial value")
	}

	// Update DB
	_, _ = db.Exec(`
		UPDATE connector_configs SET connection_url = 'postgres://after:5432/db' WHERE tenant_id = $1
	`, tenantID)

	// Without refresh, should still get cached value
	configs, _, _ = svc.GetConnectorConfigs(ctx, tenantID)
	if configs[0].ConnectionURL != "postgres://before:5432/db" {
		t.Error("Should still return cached value before refresh")
	}

	// Manual refresh
	err = svc.RefreshConnectorConfig(ctx, tenantID, "")
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// After refresh, should get new value
	configs, _, _ = svc.GetConnectorConfigs(ctx, tenantID)
	if configs[0].ConnectionURL != "postgres://after:5432/db" {
		t.Error("After refresh: expected new value")
	}
}

// TestRuntimeConfigService_MultiTenantIsolation tests tenant data isolation
func TestRuntimeConfigService_MultiTenantIsolation(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenant1 := "test_tenant_iso1_" + time.Now().Format("20060102150405")
	tenant2 := "test_tenant_iso2_" + time.Now().Format("20060102150405")
	cleanup1 := setupTestTenant(t, db, tenant1)
	cleanup2 := setupTestTenant(t, db, tenant2)
	defer cleanup1()
	defer cleanup2()

	// Insert different configs for each tenant
	_, err := db.Exec(`
		INSERT INTO connector_configs (tenant_id, connector_name, connector_type, connection_url, enabled)
		VALUES
			($1, 'tenant1_db', 'postgres', 'postgres://tenant1:5432/db', true),
			($2, 'tenant2_db', 'postgres', 'postgres://tenant2:5432/db', true)
	`, tenant1, tenant2)
	if err != nil {
		t.Fatalf("Failed to insert tenant configs: %v", err)
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 1 * time.Second,
	})

	ctx := context.Background()

	// Get configs for tenant1
	configs1, _, err := svc.GetConnectorConfigs(ctx, tenant1)
	if err != nil {
		t.Fatalf("Failed to get tenant1 configs: %v", err)
	}

	// Get configs for tenant2
	configs2, _, err := svc.GetConnectorConfigs(ctx, tenant2)
	if err != nil {
		t.Fatalf("Failed to get tenant2 configs: %v", err)
	}

	// Verify isolation - tenant1 should only see tenant1_db
	if len(configs1) != 1 || configs1[0].Name != "tenant1_db" {
		t.Errorf("Tenant1 should only see 'tenant1_db', got: %v", configs1)
	}

	// Verify isolation - tenant2 should only see tenant2_db
	if len(configs2) != 1 || configs2[0].Name != "tenant2_db" {
		t.Errorf("Tenant2 should only see 'tenant2_db', got: %v", configs2)
	}

	// Verify tenant1 cannot see tenant2's data
	for _, cfg := range configs1 {
		if cfg.TenantID != tenant1 && cfg.TenantID != "*" {
			t.Errorf("Tenant1 received data from wrong tenant: %s", cfg.TenantID)
		}
	}
}

// TestRuntimeConfigService_BlockedOperations tests dangerous operation handling
func TestRuntimeConfigService_BlockedOperations(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenantID := "test_tenant_blocked_" + time.Now().Format("20060102150405")
	cleanup := setupTestTenant(t, db, tenantID)
	defer cleanup()

	// Insert connector config
	_, err := db.Exec(`
		INSERT INTO connector_configs (tenant_id, connector_name, connector_type, connection_url, enabled)
		VALUES ($1, 'blocked_ops_test', 'postgres', 'postgres://localhost:5432/db', true)
	`, tenantID)
	if err != nil {
		t.Fatalf("Failed to insert connector: %v", err)
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 100 * time.Millisecond,
	})

	ctx := context.Background()

	// Get connector config which includes blocked operations
	cfg, _, err := svc.GetConnectorConfig(ctx, tenantID, "blocked_ops_test")
	if err != nil {
		t.Fatalf("GetConnectorConfig failed: %v", err)
	}

	// Blocked operations are stored in Options
	blockedOps, ok := cfg.Options["blocked_operations"]
	if !ok {
		t.Fatal("Expected blocked_operations in connector options")
	}

	// Convert to []string for checking
	var blocked []string
	switch v := blockedOps.(type) {
	case []string:
		blocked = v
	case []interface{}:
		for _, op := range v {
			if s, ok := op.(string); ok {
				blocked = append(blocked, s)
			}
		}
	}

	// Postgres should have DROP, DELETE, TRUNCATE, etc. blocked by default (from migration seed)
	expectedBlocked := []string{"DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT", "REVOKE"}
	for _, op := range expectedBlocked {
		found := false
		for _, b := range blocked {
			if b == op {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected '%s' to be blocked for postgres, blocked ops: %v", op, blocked)
		}
	}
}

// TestRuntimeConfigService_GetSpecificConnector tests getting a single connector by name
func TestRuntimeConfigService_GetSpecificConnector(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenantID := "test_tenant_specific_" + time.Now().Format("20060102150405")
	cleanup := setupTestTenant(t, db, tenantID)
	defer cleanup()

	// Insert multiple connectors
	_, err := db.Exec(`
		INSERT INTO connector_configs (tenant_id, connector_name, connector_type, connection_url, enabled)
		VALUES
			($1, 'postgres_main', 'postgres', 'postgres://main:5432/db', true),
			($1, 'postgres_readonly', 'postgres', 'postgres://readonly:5432/db', true),
			($1, 'salesforce_prod', 'salesforce', 'https://salesforce.com/api', true)
	`, tenantID)
	if err != nil {
		t.Fatalf("Failed to insert connectors: %v", err)
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 100 * time.Millisecond,
	})

	ctx := context.Background()

	// Get specific connector
	cfg, _, err := svc.GetConnectorConfig(ctx, tenantID, "postgres_readonly")
	if err != nil {
		t.Fatalf("GetConnectorConfig failed: %v", err)
	}

	if cfg == nil {
		t.Fatal("Expected to find connector 'postgres_readonly'")
	}

	if cfg.Name != "postgres_readonly" {
		t.Errorf("Expected name 'postgres_readonly', got '%s'", cfg.Name)
	}

	if cfg.ConnectionURL != "postgres://readonly:5432/db" {
		t.Errorf("Unexpected connection URL: %s", cfg.ConnectionURL)
	}

	// Try to get non-existent connector - should return error
	cfg, _, err = svc.GetConnectorConfig(ctx, tenantID, "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent connector")
	}
}

// TestRuntimeConfigService_LLMProviderRouting tests provider selection with routing weights
func TestRuntimeConfigService_LLMProviderRouting(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	tenantID := "test_tenant_routing_" + time.Now().Format("20060102150405")
	cleanup := setupTestTenant(t, db, tenantID)
	defer cleanup()

	// Insert providers with different priorities and weights
	_, err := db.Exec(`
		INSERT INTO llm_provider_configs (tenant_id, provider_name, config, priority, weight, enabled)
		VALUES
			($1, 'bedrock', '{"region": "us-east-1"}', 10, 0.60, true),
			($1, 'openai', '{"model": "gpt-4"}', 5, 0.40, true)
	`, tenantID)
	if err != nil {
		t.Fatalf("Failed to insert LLM providers: %v", err)
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		DB:       db,
		CacheTTL: 100 * time.Millisecond,
	})

	ctx := context.Background()
	configs, _, err := svc.GetLLMProviderConfigs(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetLLMProviderConfigs failed: %v", err)
	}

	// Verify routing weights are preserved
	var totalWeight float64
	for _, cfg := range configs {
		totalWeight += cfg.Weight
	}

	// Total weight should be 1.0 (0.60 + 0.40)
	if totalWeight < 0.99 || totalWeight > 1.01 {
		t.Errorf("Expected total weight ~1.0, got %.2f", totalWeight)
	}

	// Verify priority ordering (bedrock first)
	if len(configs) >= 2 {
		if configs[0].Priority <= configs[1].Priority {
			t.Errorf("Expected configs ordered by priority DESC, got %d <= %d",
				configs[0].Priority, configs[1].Priority)
		}
	}
}

// TestYAMLConfigFileLoader_Integration tests loading config from actual YAML file
func TestYAMLConfigFileLoader_Integration(t *testing.T) {
	// Create a temp YAML config file
	tempFile, err := os.CreateTemp("", "axonflow_config_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Set an env var for expansion test
	os.Setenv("TEST_DB_HOST", "expanded-host.example.com")
	defer os.Unsetenv("TEST_DB_HOST")

	// YAML format must match ConfigFile structure
	yamlContent := `version: "1.0"
connectors:
  test_postgres:
    type: postgres
    enabled: true
    connection_url: "postgres://${TEST_DB_HOST}:5432/testdb"
    timeout_ms: 30000
    max_retries: 3
    options:
      ssl_mode: require

llm_providers:
  bedrock:
    enabled: true
    display_name: "Amazon Bedrock"
    config:
      region: "us-west-2"
      model: "anthropic.claude-3-sonnet"
    priority: 10
    weight: 1.0
`
	if _, err := tempFile.WriteString(yamlContent); err != nil {
		t.Fatalf("Failed to write YAML config: %v", err)
	}
	tempFile.Close()

	loader, err := NewYAMLConfigFileLoader(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to create loader: %v", err)
	}

	// Test loading connectors
	connectors, err := loader.LoadConnectors("any_tenant")
	if err != nil {
		t.Fatalf("LoadConnectors failed: %v", err)
	}

	if len(connectors) != 1 {
		t.Fatalf("Expected 1 connector, got %d", len(connectors))
	}

	// Verify env var expansion
	expectedURL := "postgres://expanded-host.example.com:5432/testdb"
	if connectors[0].ConnectionURL != expectedURL {
		t.Errorf("Expected env var expansion, got URL: %s", connectors[0].ConnectionURL)
	}

	// Test loading LLM providers
	providers, err := loader.LoadLLMProviders("any_tenant")
	if err != nil {
		t.Fatalf("LoadLLMProviders failed: %v", err)
	}

	if len(providers) != 1 {
		t.Fatalf("Expected 1 LLM provider, got %d", len(providers))
	}

	if providers[0].ProviderName != "bedrock" {
		t.Errorf("Expected provider 'bedrock', got '%s'", providers[0].ProviderName)
	}
}
