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

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/config"
)

// integrationMockConnector implements base.Connector for integration tests
type integrationMockConnector struct {
	connectorType string
	connected     bool
	mu            sync.Mutex
}

func (m *integrationMockConnector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = true
	return nil
}

func (m *integrationMockConnector) Disconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *integrationMockConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{Healthy: true}, nil
}

func (m *integrationMockConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return &base.QueryResult{
		Rows:     []map[string]interface{}{{"test": "data"}},
		RowCount: 1,
	}, nil
}

func (m *integrationMockConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return &base.CommandResult{Success: true}, nil
}

func (m *integrationMockConnector) Name() string           { return "integration-mock" }
func (m *integrationMockConnector) Type() string           { return m.connectorType }
func (m *integrationMockConnector) Version() string        { return "1.0.0" }
func (m *integrationMockConnector) Capabilities() []string { return []string{"query", "execute"} }

// integrationConfigFileLoader implements config.ConfigFileLoader for tests
type integrationConfigFileLoader struct {
	connectors []*base.ConnectorConfig
}

func (l *integrationConfigFileLoader) LoadConnectors(tenantID string) ([]*base.ConnectorConfig, error) {
	return l.connectors, nil
}

func (l *integrationConfigFileLoader) LoadLLMProviders(tenantID string) ([]*config.LLMProviderConfig, error) {
	return nil, nil
}

// TestIntegration_EndToEndFlow tests the complete integration flow
func TestIntegration_EndToEndFlow(t *testing.T) {
	// 1. Setup mock config service
	mockConfigSvc := config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})
	mockConfigSvc.SetConfigFileLoader(&integrationConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{
				Name:    "postgres-main",
				Type:    "postgres",
				Timeout: 30 * time.Second,
			},
			{
				Name:    "mysql-main",
				Type:    "mysql",
				Timeout: 30 * time.Second,
			},
		},
	})

	// 2. Setup factory with mock connectors
	factory := func(connectorType string) (base.Connector, error) {
		return &integrationMockConnector{connectorType: connectorType}, nil
	}

	// 3. Initialize registry
	registry := InitTenantConnectorRegistry(mockConfigSvc, factory)
	defer func() {
		clearTenantConnectorRegistry()
	}()

	if registry == nil {
		t.Fatal("Failed to initialize TenantConnectorRegistry")
	}

	ctx := context.Background()

	// 4. Test GetConnector for tenant-a
	connA, err := registry.GetConnector(ctx, "tenant-a", "postgres-main")
	if err != nil {
		t.Fatalf("Failed to get connector for tenant-a: %v", err)
	}
	if connA.Type() != "postgres" {
		t.Errorf("Expected connector type 'postgres', got '%s'", connA.Type())
	}

	// 5. Test GetConnector for tenant-b
	connB, err := registry.GetConnector(ctx, "tenant-b", "mysql-main")
	if err != nil {
		t.Fatalf("Failed to get connector for tenant-b: %v", err)
	}
	if connB.Type() != "mysql" {
		t.Errorf("Expected connector type 'mysql', got '%s'", connB.Type())
	}

	// 6. Verify cache miss on first access
	stats := registry.GetStats()
	if stats.Misses != 2 {
		t.Errorf("Expected 2 cache misses, got %d", stats.Misses)
	}

	// Get same connector again - should be cache hit
	_, _ = registry.GetConnector(ctx, "tenant-a", "postgres-main")
	stats = registry.GetStats()
	if stats.Hits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.Hits)
	}

	// 7. Test refresh
	err = registry.RefreshConnector(ctx, "tenant-a", "postgres-main")
	if err != nil {
		t.Errorf("RefreshConnector failed: %v", err)
	}

	stats = registry.GetStats()
	if stats.Evictions != 1 {
		t.Errorf("Expected 1 eviction, got %d", stats.Evictions)
	}

	// 8. Test tenant isolation - after refresh, tenant-a should have 0 connectors
	if registry.CountByTenant("tenant-a") != 0 {
		t.Error("Expected 0 connectors for tenant-a after refresh")
	}
	if registry.CountByTenant("tenant-b") != 1 {
		t.Error("Expected 1 connector for tenant-b (not affected by tenant-a refresh)")
	}
}

// TestIntegration_RefreshAPIEndToEnd tests the refresh API endpoints
func TestIntegration_RefreshAPIEndToEnd(t *testing.T) {
	// Setup
	mockConfigSvc := config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})
	factory := func(connectorType string) (base.Connector, error) {
		return &integrationMockConnector{connectorType: connectorType}, nil
	}
	InitTenantConnectorRegistry(mockConfigSvc, factory)
	defer clearTenantConnectorRegistry()

	// Create router with handlers
	r := mux.NewRouter()
	RegisterConnectorRefreshHandlers(r)

	// Test refresh all endpoint
	t.Run("refresh all", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/connectors/refresh", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var resp ConnectorRefreshResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if !resp.Success {
			t.Error("Expected success=true")
		}
		if resp.Scope != "all" {
			t.Errorf("Expected scope 'all', got '%s'", resp.Scope)
		}
	})

	// Test cache stats endpoint
	t.Run("cache stats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/connectors/cache/stats", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var stats map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if stats["registry_enabled"] != true {
			t.Error("Expected registry_enabled=true")
		}
	})

	// Test tenant refresh endpoint
	t.Run("refresh tenant", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/connectors/refresh/test-tenant", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	// Test specific connector refresh endpoint
	t.Run("refresh connector", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/connectors/refresh/test-tenant/test-connector", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

// TestIntegration_GetConnectorForTenantFallback tests the fallback behavior
func TestIntegration_GetConnectorForTenantFallback(t *testing.T) {
	// Clear any existing registry
	clearTenantConnectorRegistry()

	// Initialize static MCP registry
	if err := InitializeMCPRegistry(); err != nil {
		// MCP registry may not be initialized in test environment, that's ok
		t.Skip("MCP registry not available in test environment")
	}
	defer func() {
		if mcpRegistry != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			mcpRegistry.DisconnectAll(ctx)
		}
	}()

	// Without TenantConnectorRegistry, GetConnectorForTenant should use static registry
	ctx := context.Background()

	// This will fail since no connector is registered, but it tests the fallback path
	_, err := GetConnectorForTenant(ctx, "any-tenant", "nonexistent-connector")
	if err == nil {
		t.Error("Expected error for nonexistent connector")
	}
}

// TestIntegration_ConcurrentAccess tests concurrent access patterns
func TestIntegration_ConcurrentAccess(t *testing.T) {
	// Setup
	mockConfigSvc := config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})
	mockConfigSvc.SetConfigFileLoader(&integrationConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "db1", Type: "postgres", Timeout: 30 * time.Second},
			{Name: "db2", Type: "mysql", Timeout: 30 * time.Second},
			{Name: "db3", Type: "redis", Timeout: 30 * time.Second},
		},
	})

	factory := func(connectorType string) (base.Connector, error) {
		return &integrationMockConnector{connectorType: connectorType}, nil
	}

	registry := InitTenantConnectorRegistry(mockConfigSvc, factory)
	defer clearTenantConnectorRegistry()

	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrent GetConnector calls
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tenant := []string{"tenant-1", "tenant-2", "tenant-3"}[idx%3]
			connector := []string{"db1", "db2", "db3"}[idx%3]
			_, _ = registry.GetConnector(ctx, tenant, connector)
		}(i)
	}

	// Concurrent refresh calls
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tenant := []string{"tenant-1", "tenant-2", "tenant-3"}[idx%3]
			_ = registry.RefreshTenant(ctx, tenant)
		}(i)
	}

	// Concurrent stats calls
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.GetStats()
			_ = registry.HitRate()
			_ = registry.Count()
		}()
	}

	wg.Wait()
	// Test passes if no deadlocks or panics
}

// TestIntegration_PeriodicCleanup tests the periodic cleanup goroutine
func TestIntegration_PeriodicCleanup(t *testing.T) {
	// Setup with short TTL
	mockConfigSvc := config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})
	mockConfigSvc.SetConfigFileLoader(&integrationConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "db1", Type: "postgres", Timeout: 30 * time.Second},
		},
	})

	factory := func(connectorType string) (base.Connector, error) {
		return &integrationMockConnector{connectorType: connectorType}, nil
	}

	registry := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		ConfigService: mockConfigSvc,
		Factory:       factory,
		CacheTTL:      50 * time.Millisecond, // Very short TTL for testing
	})

	SetTenantConnectorRegistry(registry)
	defer clearTenantConnectorRegistry()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start cleanup with short interval
	registry.StartPeriodicCleanup(ctx, 100*time.Millisecond)

	// Get a connector to cache it
	_, err := registry.GetConnector(ctx, "tenant-1", "db1")
	if err != nil {
		t.Fatalf("Failed to get connector: %v", err)
	}

	// Verify it's cached
	if registry.Count() != 1 {
		t.Errorf("Expected 1 cached connector, got %d", registry.Count())
	}

	// Wait for TTL to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Verify cleanup ran
	stats := registry.GetStats()
	if stats.Evictions < 1 {
		t.Errorf("Expected at least 1 eviction from periodic cleanup, got %d", stats.Evictions)
	}
}

// BenchmarkGetConnector benchmarks connector retrieval
func BenchmarkGetConnector(b *testing.B) {
	mockConfigSvc := config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})
	mockConfigSvc.SetConfigFileLoader(&integrationConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "db1", Type: "postgres", Timeout: 30 * time.Second},
		},
	})

	factory := func(connectorType string) (base.Connector, error) {
		return &integrationMockConnector{connectorType: connectorType}, nil
	}

	registry := InitTenantConnectorRegistry(mockConfigSvc, factory)
	defer clearTenantConnectorRegistry()

	ctx := context.Background()

	// Pre-warm cache
	_, _ = registry.GetConnector(ctx, "tenant-1", "db1")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = registry.GetConnector(ctx, "tenant-1", "db1")
	}
}

// BenchmarkGetConnectorParallel benchmarks parallel connector retrieval
func BenchmarkGetConnectorParallel(b *testing.B) {
	mockConfigSvc := config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})
	mockConfigSvc.SetConfigFileLoader(&integrationConfigFileLoader{
		connectors: []*base.ConnectorConfig{
			{Name: "db1", Type: "postgres", Timeout: 30 * time.Second},
		},
	})

	factory := func(connectorType string) (base.Connector, error) {
		return &integrationMockConnector{connectorType: connectorType}, nil
	}

	registry := InitTenantConnectorRegistry(mockConfigSvc, factory)
	defer clearTenantConnectorRegistry()

	ctx := context.Background()

	// Pre-warm cache
	_, _ = registry.GetConnector(ctx, "tenant-1", "db1")

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = registry.GetConnector(ctx, "tenant-1", "db1")
		}
	})
}
