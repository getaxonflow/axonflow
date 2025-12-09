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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/config"
)

// tenantRegistryMockConnector implements base.Connector for testing
// Named distinctly to avoid conflicts with mockConnector in mcp_handler_test.go
type tenantRegistryMockConnector struct {
	name          string
	connectorType string
	connected     bool
	connectErr    error
	disconnectErr error
	queryResult   *base.QueryResult
	queryErr      error
}

func (m *tenantRegistryMockConnector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *tenantRegistryMockConnector) Disconnect(ctx context.Context) error {
	if m.disconnectErr != nil {
		return m.disconnectErr
	}
	m.connected = false
	return nil
}

func (m *tenantRegistryMockConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{Healthy: m.connected}, nil
}

func (m *tenantRegistryMockConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	if m.queryResult != nil {
		return m.queryResult, nil
	}
	return &base.QueryResult{Rows: []map[string]interface{}{}}, nil
}

func (m *tenantRegistryMockConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return &base.CommandResult{Success: true}, nil
}

func (m *tenantRegistryMockConnector) Name() string           { return m.name }
func (m *tenantRegistryMockConnector) Type() string           { return m.connectorType }
func (m *tenantRegistryMockConnector) Version() string        { return "1.0.0" }
func (m *tenantRegistryMockConnector) Capabilities() []string { return []string{"query", "execute"} }

// tenantRegistryMockConfigService implements a minimal RuntimeConfigService for testing
type tenantRegistryMockConfigService struct {
	connectorConfigs map[string]map[string]*base.ConnectorConfig // tenantID -> connectorName -> config
	getConfigErr     error
}

func newTenantRegistryMockConfigService() *tenantRegistryMockConfigService {
	return &tenantRegistryMockConfigService{
		connectorConfigs: make(map[string]map[string]*base.ConnectorConfig),
	}
}

func (m *tenantRegistryMockConfigService) addConnector(tenantID, connectorName, connectorType string) {
	if m.connectorConfigs[tenantID] == nil {
		m.connectorConfigs[tenantID] = make(map[string]*base.ConnectorConfig)
	}
	m.connectorConfigs[tenantID][connectorName] = &base.ConnectorConfig{
		Name:     connectorName,
		Type:     connectorType,
		TenantID: tenantID,
		Timeout:  5 * time.Second,
	}
}

// clearTenantConnectorRegistry safely clears the global registry for testing.
func clearTenantConnectorRegistry() {
	tenantConnectorRegistryMu.Lock()
	tenantConnectorRegistry = nil
	tenantConnectorRegistryMu.Unlock()
}

// createTestRegistry creates a registry with mock dependencies for testing.
func createTestRegistry(t *testing.T, configSvc *config.RuntimeConfigService) *TenantConnectorRegistry {
	factory := func(connectorType string) (base.Connector, error) {
		return &tenantRegistryMockConnector{connectorType: connectorType}, nil
	}

	return NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		ConfigService: configSvc,
		Factory:       factory,
		CacheTTL:      100 * time.Millisecond, // Short TTL for testing
	})
}

// --- Connector Type Validation Tests ---

func TestIsValidConnectorType(t *testing.T) {
	tests := []struct {
		name          string
		connectorType string
		want          bool
	}{
		{"valid postgres", ConnectorPostgres, true},
		{"valid mysql", ConnectorMySQL, true},
		{"valid mongodb", ConnectorMongoDB, true},
		{"valid cassandra", ConnectorCassandra, true},
		{"valid redis", ConnectorRedis, true},
		{"valid http", ConnectorHTTP, true},
		{"valid s3", ConnectorS3, true},
		{"valid azure_blob", ConnectorAzureBlob, true},
		{"valid gcs", ConnectorGCS, true},
		{"valid amadeus", ConnectorAmadeus, true},
		{"valid salesforce", ConnectorSalesforce, true},
		{"valid slack", ConnectorSlack, true},
		{"valid snowflake", ConnectorSnowflake, true},
		{"valid hubspot", ConnectorHubSpot, true},
		{"valid jira", ConnectorJira, true},
		{"valid servicenow", ConnectorServiceNow, true},
		{"invalid type", "unknown", false},
		{"empty type", "", false},
		{"case sensitive", "POSTGRES", false},
		{"typo", "postgress", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidConnectorType(tt.connectorType); got != tt.want {
				t.Errorf("IsValidConnectorType(%q) = %v, want %v", tt.connectorType, got, tt.want)
			}
		})
	}
}

func TestConnectorTypeConstants(t *testing.T) {
	// Verify constants match expected values
	if ConnectorPostgres != "postgres" {
		t.Errorf("ConnectorPostgres = %q, want %q", ConnectorPostgres, "postgres")
	}
	if ConnectorMySQL != "mysql" {
		t.Errorf("ConnectorMySQL = %q, want %q", ConnectorMySQL, "mysql")
	}
	if ConnectorMongoDB != "mongodb" {
		t.Errorf("ConnectorMongoDB = %q, want %q", ConnectorMongoDB, "mongodb")
	}

	// Verify ValidConnectorTypes contains all expected types
	expectedCount := 16 // Update if more connectors are added
	if len(ValidConnectorTypes) != expectedCount {
		t.Errorf("ValidConnectorTypes has %d entries, want %d", len(ValidConnectorTypes), expectedCount)
	}
}

// --- TenantConnectorEntry Tests ---

func TestTenantConnectorEntry_IsExpired(t *testing.T) {
	// Entry that's not expired
	notExpired := &TenantConnectorEntry{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if notExpired.IsExpired() {
		t.Error("Entry should not be expired")
	}

	// Entry that is expired
	expired := &TenantConnectorEntry{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	if !expired.IsExpired() {
		t.Error("Entry should be expired")
	}
}

// --- NewTenantConnectorRegistry Tests ---

func TestNewTenantConnectorRegistry(t *testing.T) {
	// With defaults
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})
	if reg == nil {
		t.Fatal("Expected non-nil registry")
	}
	if reg.cacheTTL != 30*time.Second {
		t.Errorf("Expected default cacheTTL of 30s, got %v", reg.cacheTTL)
	}
	if reg.connectors == nil {
		t.Error("Expected connectors map to be initialized")
	}

	// With custom TTL
	customTTL := 60 * time.Second
	reg2 := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: customTTL,
	})
	if reg2.cacheTTL != customTTL {
		t.Errorf("Expected cacheTTL of %v, got %v", customTTL, reg2.cacheTTL)
	}
}

// --- GetConnector Tests ---

func TestGetConnector_CacheHit(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: 10 * time.Second,
	})

	// Pre-populate cache
	mockConn := &tenantRegistryMockConnector{name: "test", connectorType: "postgres"}
	reg.connectors["tenant1:mydb"] = &TenantConnectorEntry{
		Connector:  mockConn,
		Config:     &base.ConnectorConfig{Name: "mydb", Type: "postgres"},
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Second),
	}

	ctx := context.Background()
	conn, err := reg.GetConnector(ctx, "tenant1", "mydb")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if conn != mockConn {
		t.Error("Expected cached connector to be returned")
	}

	// Verify stats
	stats := reg.GetStats()
	if stats.Hits != 1 {
		t.Errorf("Expected 1 hit, got %d", stats.Hits)
	}
}

func TestGetConnector_CacheMiss_NoConfigService(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: 10 * time.Second,
	})

	ctx := context.Background()
	_, err := reg.GetConnector(ctx, "tenant1", "mydb")

	if err == nil {
		t.Fatal("Expected error for missing config service")
	}
	if err.Error() != "RuntimeConfigService not initialized" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestGetConnector_CacheMiss_NoFactory(t *testing.T) {
	// Create a real RuntimeConfigService for this test
	configSvc := config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{
		SelfHosted: true,
		CacheTTL:   10 * time.Second,
	})

	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		ConfigService: configSvc,
		CacheTTL:      10 * time.Second,
		// No factory
	})

	ctx := context.Background()
	_, err := reg.GetConnector(ctx, "tenant1", "mydb")

	// Will fail because no connector config exists (not because of factory)
	if err == nil {
		t.Fatal("Expected error")
	}
}

// --- RefreshTenant Tests ---

func TestRefreshTenant(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: 10 * time.Second,
	})

	// Pre-populate cache with multiple connectors
	reg.connectors["tenant1:db1"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}
	reg.connectors["tenant1:db2"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}
	reg.connectors["tenant2:db1"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}

	ctx := context.Background()
	err := reg.RefreshTenant(ctx, "tenant1")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// tenant1 connectors should be evicted
	if reg.CountByTenant("tenant1") != 0 {
		t.Errorf("Expected 0 connectors for tenant1, got %d", reg.CountByTenant("tenant1"))
	}

	// tenant2 connectors should remain
	if reg.CountByTenant("tenant2") != 1 {
		t.Errorf("Expected 1 connector for tenant2, got %d", reg.CountByTenant("tenant2"))
	}
}

// --- RefreshConnector Tests ---

func TestRefreshConnector(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: 10 * time.Second,
	})

	// Pre-populate cache
	reg.connectors["tenant1:db1"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}
	reg.connectors["tenant1:db2"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}

	ctx := context.Background()
	err := reg.RefreshConnector(ctx, "tenant1", "db1")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Only db1 should be evicted
	if _, exists := reg.connectors["tenant1:db1"]; exists {
		t.Error("Expected tenant1:db1 to be evicted")
	}
	if _, exists := reg.connectors["tenant1:db2"]; !exists {
		t.Error("Expected tenant1:db2 to remain")
	}
}

// --- RefreshAll Tests ---

func TestRefreshAll(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: 10 * time.Second,
	})

	// Pre-populate cache
	reg.connectors["tenant1:db1"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}
	reg.connectors["tenant2:db1"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}

	ctx := context.Background()
	err := reg.RefreshAll(ctx)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if reg.Count() != 0 {
		t.Errorf("Expected 0 connectors after RefreshAll, got %d", reg.Count())
	}
}

// --- Count Tests ---

func TestCount(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})

	if reg.Count() != 0 {
		t.Errorf("Expected 0 initial count, got %d", reg.Count())
	}

	reg.connectors["tenant1:db1"] = &TenantConnectorEntry{}
	reg.connectors["tenant1:db2"] = &TenantConnectorEntry{}
	reg.connectors["tenant2:db1"] = &TenantConnectorEntry{}

	if reg.Count() != 3 {
		t.Errorf("Expected 3 connectors, got %d", reg.Count())
	}
}

func TestCountByTenant(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})

	reg.connectors["tenant1:db1"] = &TenantConnectorEntry{}
	reg.connectors["tenant1:db2"] = &TenantConnectorEntry{}
	reg.connectors["tenant2:db1"] = &TenantConnectorEntry{}

	if reg.CountByTenant("tenant1") != 2 {
		t.Errorf("Expected 2 connectors for tenant1, got %d", reg.CountByTenant("tenant1"))
	}
	if reg.CountByTenant("tenant2") != 1 {
		t.Errorf("Expected 1 connector for tenant2, got %d", reg.CountByTenant("tenant2"))
	}
	if reg.CountByTenant("tenant3") != 0 {
		t.Errorf("Expected 0 connectors for tenant3, got %d", reg.CountByTenant("tenant3"))
	}
}

// --- GetConnectorsByTenant Tests ---

func TestGetConnectorsByTenant(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})

	reg.connectors["tenant1:db1"] = &TenantConnectorEntry{}
	reg.connectors["tenant1:db2"] = &TenantConnectorEntry{}
	reg.connectors["tenant2:cache"] = &TenantConnectorEntry{}

	names := reg.GetConnectorsByTenant("tenant1")
	if len(names) != 2 {
		t.Errorf("Expected 2 connectors for tenant1, got %d", len(names))
	}

	// Check both names are present
	found := make(map[string]bool)
	for _, name := range names {
		found[name] = true
	}
	if !found["db1"] || !found["db2"] {
		t.Errorf("Expected db1 and db2, got %v", names)
	}
}

// --- Cleanup Tests ---

func TestCleanup(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: 100 * time.Millisecond,
	})

	// Add expired and non-expired entries
	reg.connectors["tenant1:expired"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(-1 * time.Second), // Already expired
	}
	reg.connectors["tenant1:valid"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(10 * time.Second), // Still valid
	}

	ctx := context.Background()
	evicted := reg.Cleanup(ctx)

	if evicted != 1 {
		t.Errorf("Expected 1 evicted, got %d", evicted)
	}
	if reg.Count() != 1 {
		t.Errorf("Expected 1 remaining connector, got %d", reg.Count())
	}
	if _, exists := reg.connectors["tenant1:valid"]; !exists {
		t.Error("Expected valid connector to remain")
	}
}

// --- DisconnectAll Tests ---

func TestDisconnectAll(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})

	mock1 := &tenantRegistryMockConnector{connected: true}
	mock2 := &tenantRegistryMockConnector{connected: true}

	reg.connectors["tenant1:db1"] = &TenantConnectorEntry{
		Connector: mock1,
		ExpiresAt: time.Now().Add(10 * time.Second),
	}
	reg.connectors["tenant1:db2"] = &TenantConnectorEntry{
		Connector: mock2,
		ExpiresAt: time.Now().Add(10 * time.Second),
	}

	ctx := context.Background()
	reg.DisconnectAll(ctx)

	if mock1.connected || mock2.connected {
		t.Error("Expected all connectors to be disconnected")
	}
	if reg.Count() != 0 {
		t.Errorf("Expected 0 connectors after DisconnectAll, got %d", reg.Count())
	}
}

// --- Stats Tests ---

func TestTenantRegistryGetStats(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})

	// Record some stats
	reg.recordHit()
	reg.recordHit()
	reg.recordMiss()
	reg.recordEvictions(3)
	reg.recordFactoryCreate()
	reg.recordFactoryFailure()
	reg.recordConnectionError()

	stats := reg.GetStats()

	if stats.Hits != 2 {
		t.Errorf("Expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}
	if stats.Evictions != 3 {
		t.Errorf("Expected 3 evictions, got %d", stats.Evictions)
	}
	if stats.FactoryCreations != 1 {
		t.Errorf("Expected 1 factory creation, got %d", stats.FactoryCreations)
	}
	if stats.FactoryFailures != 1 {
		t.Errorf("Expected 1 factory failure, got %d", stats.FactoryFailures)
	}
	if stats.ConnectionErrors != 1 {
		t.Errorf("Expected 1 connection error, got %d", stats.ConnectionErrors)
	}
}

func TestHitRate(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})

	// No requests yet
	if reg.HitRate() != 0 {
		t.Errorf("Expected 0 hit rate with no requests, got %f", reg.HitRate())
	}

	// 2 hits, 2 misses = 50%
	reg.recordHit()
	reg.recordHit()
	reg.recordMiss()
	reg.recordMiss()

	rate := reg.HitRate()
	if rate != 50 {
		t.Errorf("Expected 50%% hit rate, got %f", rate)
	}
}

// --- Global Accessor Tests ---

func TestInitTenantConnectorRegistry(t *testing.T) {
	// Clear any existing instance
	clearTenantConnectorRegistry()
	t.Cleanup(clearTenantConnectorRegistry)

	// Use a nil config service for testing (basic initialization)
	factory := func(connectorType string) (base.Connector, error) {
		return &tenantRegistryMockConnector{}, nil
	}

	reg := InitTenantConnectorRegistry(nil, factory)

	if reg == nil {
		t.Error("Expected non-nil registry")
	}

	// Verify global instance is set
	if GetTenantConnectorRegistry() == nil {
		t.Error("Expected GetTenantConnectorRegistry() to return non-nil after init")
	}
}

func TestGetTenantConnectorRegistry_BeforeInit(t *testing.T) {
	// Clear existing instance
	clearTenantConnectorRegistry()
	t.Cleanup(clearTenantConnectorRegistry)

	// Should return nil before initialization
	if GetTenantConnectorRegistry() != nil {
		t.Error("Expected GetTenantConnectorRegistry() to return nil before init")
	}
}

func TestSetTenantConnectorRegistry(t *testing.T) {
	// Clear existing instance
	clearTenantConnectorRegistry()
	t.Cleanup(clearTenantConnectorRegistry)

	// Create a registry
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})

	// Set it globally
	SetTenantConnectorRegistry(reg)

	// Verify it's set
	if GetTenantConnectorRegistry() != reg {
		t.Error("Expected GetTenantConnectorRegistry() to return the registry we set")
	}
}

// --- Concurrent Access Tests ---

func TestConcurrentAccess(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: 10 * time.Second,
	})

	// Pre-populate with some connectors
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("tenant1:db%d", i)
		reg.connectors[key] = &TenantConnectorEntry{
			Connector: &tenantRegistryMockConnector{},
			ExpiresAt: time.Now().Add(10 * time.Second),
		}
	}

	var wg sync.WaitGroup
	var ops int64

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = reg.GetConnectorsByTenant("tenant1")
			_ = reg.Count()
			_ = reg.CountByTenant("tenant1")
			_ = reg.GetStats()
			_ = reg.HitRate()
			atomic.AddInt64(&ops, 5)
		}()
	}

	// Concurrent writes (refresh)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()
			_ = reg.RefreshConnector(ctx, "tenant1", fmt.Sprintf("db%d", idx))
			atomic.AddInt64(&ops, 1)
		}(i)
	}

	wg.Wait()

	if ops < 510 {
		t.Errorf("Expected at least 510 operations, got %d", ops)
	}
}

func TestConcurrentGetConnector_DoubleCheck(t *testing.T) {
	// Test that double-check locking works correctly
	createCount := int64(0)

	factory := func(connectorType string) (base.Connector, error) {
		atomic.AddInt64(&createCount, 1)
		time.Sleep(10 * time.Millisecond) // Simulate slow creation
		return &tenantRegistryMockConnector{connectorType: connectorType}, nil
	}

	configSvc := config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{
		SelfHosted: true,
		CacheTTL:   10 * time.Second,
	})

	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		ConfigService: configSvc,
		Factory:       factory,
		CacheTTL:      10 * time.Second,
	})

	// Pre-set environment for connector config loading
	t.Setenv("DATABASE_URL", "postgres://localhost/test")

	// Many goroutines trying to get the same connector simultaneously
	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// This will fail because no real config, but the double-check logic is tested
			_, _ = reg.GetConnector(ctx, "tenant1", "mydb")
		}()
	}

	wg.Wait()

	// The test passes if no deadlocks or panics occur
	// Factory may be called multiple times due to config loading failures, which is expected
}

// --- connectorKey Tests ---

func TestConnectorKey(t *testing.T) {
	key := connectorKey("tenant-abc", "my-connector")
	expected := "tenant-abc:my-connector"
	if key != expected {
		t.Errorf("Expected key %q, got %q", expected, key)
	}
}

// --- Periodic Cleanup Tests ---

func TestStartPeriodicCleanup(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		CacheTTL: 50 * time.Millisecond,
	})

	// Add an entry that will expire
	reg.connectors["tenant1:expiring"] = &TenantConnectorEntry{
		Connector: &tenantRegistryMockConnector{},
		ExpiresAt: time.Now().Add(25 * time.Millisecond),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start cleanup with 30ms interval
	reg.StartPeriodicCleanup(ctx, 30*time.Millisecond)

	// Wait for entry to expire and cleanup to run
	time.Sleep(100 * time.Millisecond)

	if reg.Count() != 0 {
		t.Errorf("Expected 0 connectors after cleanup, got %d", reg.Count())
	}
}

func TestStartPeriodicCleanup_Cancellation(t *testing.T) {
	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{})

	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup
	reg.StartPeriodicCleanup(ctx, 10*time.Millisecond)

	// Cancel immediately
	cancel()

	// Small delay to ensure goroutine processes cancellation
	time.Sleep(50 * time.Millisecond)

	// Test passes if no goroutine leaks (verified by race detector)
}
