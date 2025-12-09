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
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

// mockConfigFileLoader implements ConfigFileLoader for testing
type mockConfigFileLoader struct {
	connectors   []*base.ConnectorConfig
	llmProviders []*LLMProviderConfig
}

func (m *mockConfigFileLoader) LoadConnectors(tenantID string) ([]*base.ConnectorConfig, error) {
	return m.connectors, nil
}

func (m *mockConfigFileLoader) LoadLLMProviders(tenantID string) ([]*LLMProviderConfig, error) {
	return m.llmProviders, nil
}

func TestRuntimeConfigService_GetConnectorConfigs_FromEnvVars(t *testing.T) {
	// Set up env vars
	os.Setenv("DATABASE_URL", "postgres://localhost:5432/testdb")
	defer os.Unsetenv("DATABASE_URL")

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		CacheTTL: 1 * time.Second,
	})

	ctx := context.Background()
	configs, source, err := svc.GetConnectorConfigs(ctx, "test_tenant")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if source != ConfigSourceEnvVars {
		t.Errorf("expected source %s, got %s", ConfigSourceEnvVars, source)
	}

	if len(configs) == 0 {
		t.Error("expected at least one connector config")
	}

	// Verify postgres config was loaded
	var foundPostgres bool
	for _, cfg := range configs {
		if cfg.Type == "postgres" {
			foundPostgres = true
			if cfg.ConnectionURL != "postgres://localhost:5432/testdb" {
				t.Errorf("expected connection URL to match DATABASE_URL")
			}
		}
	}

	if !foundPostgres {
		t.Error("expected postgres connector to be loaded from env vars")
	}
}

func TestRuntimeConfigService_GetConnectorConfigs_FromFileLoader(t *testing.T) {
	mockLoader := &mockConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{
				Name:          "test_postgres",
				Type:          "postgres",
				ConnectionURL: "postgres://fileloader:5432/db",
				Timeout:       30 * time.Second,
				MaxRetries:    3,
				TenantID:      "*",
			},
		},
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		SelfHosted: true, // Skip database check
		CacheTTL:   1 * time.Second,
	})
	svc.SetConfigFileLoader(mockLoader)

	ctx := context.Background()
	configs, source, err := svc.GetConnectorConfigs(ctx, "test_tenant")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if source != ConfigSourceFile {
		t.Errorf("expected source %s, got %s", ConfigSourceFile, source)
	}

	if len(configs) != 1 {
		t.Errorf("expected 1 config, got %d", len(configs))
	}

	if configs[0].Name != "test_postgres" {
		t.Errorf("expected connector name 'test_postgres', got '%s'", configs[0].Name)
	}
}

func TestRuntimeConfigService_GetLLMProviderConfigs_FromEnvVars(t *testing.T) {
	os.Setenv("BEDROCK_REGION", "us-west-2")
	os.Setenv("BEDROCK_MODEL", "anthropic.claude-3-sonnet-20240229-v1:0")
	defer func() {
		os.Unsetenv("BEDROCK_REGION")
		os.Unsetenv("BEDROCK_MODEL")
	}()

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		CacheTTL: 1 * time.Second,
	})

	ctx := context.Background()
	configs, source, err := svc.GetLLMProviderConfigs(ctx, "test_tenant")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if source != ConfigSourceEnvVars {
		t.Errorf("expected source %s, got %s", ConfigSourceEnvVars, source)
	}

	if len(configs) == 0 {
		t.Error("expected at least one LLM provider config")
	}

	var foundBedrock bool
	for _, cfg := range configs {
		if cfg.ProviderName == "bedrock" {
			foundBedrock = true
			region, _ := cfg.Config["region"].(string)
			if region != "us-west-2" {
				t.Errorf("expected region 'us-west-2', got '%s'", region)
			}
		}
	}

	if !foundBedrock {
		t.Error("expected bedrock provider to be loaded from env vars")
	}
}

func TestRuntimeConfigService_CacheHit(t *testing.T) {
	mockLoader := &mockConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "cached_connector", Type: "postgres", TenantID: "*"},
		},
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		SelfHosted: true,
		CacheTTL:   5 * time.Second,
	})
	svc.SetConfigFileLoader(mockLoader)

	ctx := context.Background()

	// First call - cache miss
	_, _, err := svc.GetConnectorConfigs(ctx, "test_tenant")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Change the mock to return different data
	mockLoader.connectors = []*base.ConnectorConfig{
		{Name: "different_connector", Type: "cassandra", TenantID: "*"},
	}

	// Second call - should hit cache and return old data
	configs, _, err := svc.GetConnectorConfigs(ctx, "test_tenant")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if configs[0].Name != "cached_connector" {
		t.Error("expected cache hit to return cached data")
	}

	// Check cache hit rate
	hitRate := svc.GetCacheHitRate()
	if hitRate != 50.0 { // 1 hit, 1 miss = 50%
		t.Errorf("expected 50%% hit rate, got %.2f%%", hitRate)
	}
}

func TestRuntimeConfigService_RefreshInvalidatesCache(t *testing.T) {
	mockLoader := &mockConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "original", Type: "postgres", TenantID: "*"},
		},
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		SelfHosted: true,
		CacheTTL:   5 * time.Second,
	})
	svc.SetConfigFileLoader(mockLoader)

	ctx := context.Background()

	// First call - populates cache
	_, _, err := svc.GetConnectorConfigs(ctx, "test_tenant")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Update mock
	mockLoader.connectors = []*base.ConnectorConfig{
		{Name: "updated", Type: "cassandra", TenantID: "*"},
	}

	// Refresh cache
	err = svc.RefreshConnectorConfig(ctx, "test_tenant", "")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	// Should now get new data
	configs, _, err := svc.GetConnectorConfigs(ctx, "test_tenant")
	if err != nil {
		t.Fatalf("call after refresh failed: %v", err)
	}

	if configs[0].Name != "updated" {
		t.Error("expected refresh to invalidate cache and return new data")
	}
}

func TestConfigCache_Expiration(t *testing.T) {
	cache := NewConfigCache(50 * time.Millisecond)

	tenantID := "test_tenant"
	configs := []*base.ConnectorConfig{
		{Name: "test", Type: "postgres"},
	}

	cache.SetConnectors(tenantID, configs)

	// Should hit immediately
	cached, ok := cache.GetConnectors(tenantID)
	if !ok || len(cached) != 1 {
		t.Error("expected cache hit immediately after set")
	}

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// Should miss after expiration
	_, ok = cache.GetConnectors(tenantID)
	if ok {
		t.Error("expected cache miss after TTL expiration")
	}
}

func TestConfigCache_InvalidateSpecificConnector(t *testing.T) {
	cache := NewConfigCache(5 * time.Second)

	tenantID := "test_tenant"
	configs := []*base.ConnectorConfig{
		{Name: "connector1", Type: "postgres"},
		{Name: "connector2", Type: "cassandra"},
		{Name: "connector3", Type: "postgres"},
	}

	cache.SetConnectors(tenantID, configs)

	// Invalidate specific connector
	cache.InvalidateConnector(tenantID, "connector2")

	// Should still have cache entry but without connector2
	cached, ok := cache.GetConnectors(tenantID)
	if !ok {
		t.Error("expected cache hit after partial invalidation")
	}

	if len(cached) != 2 {
		t.Errorf("expected 2 connectors after invalidation, got %d", len(cached))
	}

	for _, cfg := range cached {
		if cfg.Name == "connector2" {
			t.Error("connector2 should have been removed from cache")
		}
	}
}

func TestRuntimeConfigService_RefreshLLMProviderConfig(t *testing.T) {
	mockLoader := &mockConfigFileLoader{
		llmProviders: []*LLMProviderConfig{
			{ProviderName: "bedrock", Enabled: true, Priority: 10},
		},
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		SelfHosted: true,
		CacheTTL:   5 * time.Second,
	})
	svc.SetConfigFileLoader(mockLoader)

	ctx := context.Background()

	// First call - populates cache
	_, _, err := svc.GetLLMProviderConfigs(ctx, "test_tenant")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Refresh specific provider
	err = svc.RefreshLLMProviderConfig(ctx, "test_tenant", "bedrock")
	if err != nil {
		t.Fatalf("RefreshLLMProviderConfig failed: %v", err)
	}

	// Should be able to call again after refresh
	_, _, err = svc.GetLLMProviderConfigs(ctx, "test_tenant")
	if err != nil {
		t.Fatalf("call after refresh failed: %v", err)
	}
}

func TestRuntimeConfigService_RefreshAllConfigs(t *testing.T) {
	mockLoader := &mockConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "test", Type: "postgres", TenantID: "*"},
		},
		llmProviders: []*LLMProviderConfig{
			{ProviderName: "bedrock", Enabled: true},
		},
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		SelfHosted: true,
		CacheTTL:   5 * time.Second,
	})
	svc.SetConfigFileLoader(mockLoader)

	ctx := context.Background()

	// Populate caches
	_, _, _ = svc.GetConnectorConfigs(ctx, "test_tenant")
	_, _, _ = svc.GetLLMProviderConfigs(ctx, "test_tenant")

	// Update mock data
	mockLoader.connectors = []*base.ConnectorConfig{
		{Name: "updated", Type: "cassandra", TenantID: "*"},
	}
	mockLoader.llmProviders = []*LLMProviderConfig{
		{ProviderName: "ollama", Enabled: true},
	}

	// Refresh all
	svc.RefreshAllConfigs()

	// Should get new data after refresh
	configs, _, _ := svc.GetConnectorConfigs(ctx, "test_tenant")
	if configs[0].Name != "updated" {
		t.Error("expected RefreshAllConfigs to invalidate connector cache")
	}

	llmConfigs, _, _ := svc.GetLLMProviderConfigs(ctx, "test_tenant")
	if llmConfigs[0].ProviderName != "ollama" {
		t.Error("expected RefreshAllConfigs to invalidate LLM provider cache")
	}
}

func TestRuntimeConfigService_GetCacheStats(t *testing.T) {
	mockLoader := &mockConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "test", Type: "postgres", TenantID: "*"},
		},
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		SelfHosted: true,
		CacheTTL:   5 * time.Second,
	})
	svc.SetConfigFileLoader(mockLoader)

	ctx := context.Background()

	// Make some calls to generate cache activity
	_, _, _ = svc.GetConnectorConfigs(ctx, "tenant1") // miss
	_, _, _ = svc.GetConnectorConfigs(ctx, "tenant1") // hit
	_, _, _ = svc.GetConnectorConfigs(ctx, "tenant2") // miss
	_, _, _ = svc.GetConnectorConfigs(ctx, "tenant2") // hit

	stats := svc.GetCacheStats()

	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 2 {
		t.Errorf("expected 2 misses, got %d", stats.Misses)
	}

	hitRate := svc.GetCacheHitRate()
	if hitRate != 50.0 {
		t.Errorf("expected 50%% hit rate, got %.2f%%", hitRate)
	}
}

func TestRuntimeConfigService_GetConnectorConfig(t *testing.T) {
	mockLoader := &mockConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "pg1", Type: "postgres", TenantID: "*"},
			{Name: "pg2", Type: "postgres", TenantID: "tenant1"},
		},
	}

	svc := NewRuntimeConfigService(RuntimeConfigServiceOptions{
		SelfHosted: true,
		CacheTTL:   5 * time.Second,
	})
	svc.SetConfigFileLoader(mockLoader)

	ctx := context.Background()

	t.Run("found connector", func(t *testing.T) {
		cfg, _, err := svc.GetConnectorConfig(ctx, "tenant1", "pg1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Error("expected non-nil config")
		}
		if cfg.Name != "pg1" {
			t.Errorf("expected name 'pg1', got '%s'", cfg.Name)
		}
	})

	t.Run("connector not found", func(t *testing.T) {
		cfg, _, err := svc.GetConnectorConfig(ctx, "tenant1", "nonexistent")
		// Function returns error when connector not found
		if err == nil {
			t.Error("expected error for nonexistent connector")
		}
		if cfg != nil {
			t.Error("expected nil config for nonexistent connector")
		}
	})
}
