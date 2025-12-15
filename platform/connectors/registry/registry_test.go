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

package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

// mockConnector implements base.Connector for testing
type mockConnector struct {
	name         string
	connType     string
	connected    bool
	healthy      bool
	healthErr    error
	connectErr   error
	disconnectErr error
}

func (m *mockConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *mockConnector) Disconnect(ctx context.Context) error {
	if m.disconnectErr != nil {
		return m.disconnectErr
	}
	m.connected = false
	return nil
}

func (m *mockConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if m.healthErr != nil {
		return nil, m.healthErr
	}
	return &base.HealthStatus{
		Healthy:   m.healthy,
		Latency:   10 * time.Millisecond,
		Timestamp: time.Now(),
	}, nil
}

func (m *mockConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return &base.QueryResult{Rows: []map[string]interface{}{}}, nil
}

func (m *mockConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return &base.CommandResult{Success: true}, nil
}

func (m *mockConnector) Name() string      { return m.name }
func (m *mockConnector) Type() string      { return m.connType }
func (m *mockConnector) Version() string   { return "1.0.0" }
func (m *mockConnector) Capabilities() []string { return []string{"query", "execute"} }

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()
	if registry == nil {
		t.Fatal("expected non-nil registry")
	}
	if registry.connectors == nil {
		t.Error("expected connectors map to be initialized")
	}
	if registry.configs == nil {
		t.Error("expected configs map to be initialized")
	}
	if registry.storage != nil {
		t.Error("expected storage to be nil for basic registry")
	}
}

func TestRegistry_Register(t *testing.T) {
	registry := NewRegistry()
	connector := &mockConnector{name: "pg1", connType: "postgres", healthy: true}
	config := &base.ConnectorConfig{
		Name:    "pg1",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	err := registry.Register("pg1", connector, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify registration
	got, err := registry.Get("pg1")
	if err != nil {
		t.Fatalf("failed to get registered connector: %v", err)
	}
	if got != connector {
		t.Error("got different connector than registered")
	}

	// Try to register same name again
	connector2 := &mockConnector{name: "pg1", connType: "postgres"}
	err = registry.Register("pg1", connector2, config)
	if err == nil {
		t.Error("expected error when registering duplicate name")
	}
}

func TestRegistry_Register_ConnectError(t *testing.T) {
	registry := NewRegistry()
	connector := &mockConnector{
		name:       "pg1",
		connType:   "postgres",
		connectErr: errors.New("connection refused"),
	}
	config := &base.ConnectorConfig{
		Name:    "pg1",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	err := registry.Register("pg1", connector, config)
	if err == nil {
		t.Error("expected error when connector fails to connect")
	}
}

func TestRegistry_Unregister(t *testing.T) {
	registry := NewRegistry()
	connector := &mockConnector{name: "pg1", connType: "postgres", healthy: true}
	config := &base.ConnectorConfig{
		Name:    "pg1",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	registry.Register("pg1", connector, config)

	err := registry.Unregister("pg1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify unregistration
	_, err = registry.Get("pg1")
	if err == nil {
		t.Error("expected error when getting unregistered connector")
	}
}

func TestRegistry_Unregister_NotFound(t *testing.T) {
	registry := NewRegistry()

	err := registry.Unregister("nonexistent")
	if err == nil {
		t.Error("expected error when unregistering nonexistent connector")
	}
}

func TestRegistry_Unregister_DisconnectError(t *testing.T) {
	registry := NewRegistry()
	connector := &mockConnector{
		name:          "pg1",
		connType:      "postgres",
		healthy:       true,
		disconnectErr: errors.New("disconnect failed"),
	}
	config := &base.ConnectorConfig{
		Name:    "pg1",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	registry.Register("pg1", connector, config)

	// Should still unregister even if disconnect fails
	err := registry.Unregister("pg1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be removed
	if registry.Count() != 0 {
		t.Error("expected connector to be removed even with disconnect error")
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	registry := NewRegistry()

	_, err := registry.Get("nonexistent")
	if err == nil {
		t.Error("expected error when getting nonexistent connector")
	}
}

func TestRegistry_GetConfig(t *testing.T) {
	registry := NewRegistry()
	connector := &mockConnector{name: "pg1", connType: "postgres", healthy: true}
	config := &base.ConnectorConfig{
		Name:          "pg1",
		Type:          "postgres",
		ConnectionURL: "postgres://localhost:5432/test",
		Timeout:       5 * time.Second,
	}

	registry.Register("pg1", connector, config)

	got, err := registry.GetConfig("pg1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ConnectionURL != config.ConnectionURL {
		t.Errorf("expected ConnectionURL %q, got %q", config.ConnectionURL, got.ConnectionURL)
	}
}

func TestRegistry_GetConfig_NotFound(t *testing.T) {
	registry := NewRegistry()

	_, err := registry.GetConfig("nonexistent")
	if err == nil {
		t.Error("expected error when getting config for nonexistent connector")
	}
}

func TestRegistry_List(t *testing.T) {
	registry := NewRegistry()

	// Empty registry
	names := registry.List()
	if len(names) != 0 {
		t.Errorf("expected empty list, got %d items", len(names))
	}

	// Add connectors
	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg1", &mockConnector{name: "pg1", connType: "postgres"}, config)
	config2 := &base.ConnectorConfig{Name: "pg2", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg2", &mockConnector{name: "pg2", connType: "postgres"}, config2)

	names = registry.List()
	if len(names) != 2 {
		t.Errorf("expected 2 connectors, got %d", len(names))
	}
}

func TestRegistry_ListWithTypes(t *testing.T) {
	registry := NewRegistry()

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg1", &mockConnector{name: "pg1", connType: "postgres"}, config)
	config2 := &base.ConnectorConfig{Name: "cass1", Type: "cassandra", Timeout: 5 * time.Second}
	registry.Register("cass1", &mockConnector{name: "cass1", connType: "cassandra"}, config2)

	result := registry.ListWithTypes()
	if result["pg1"] != "postgres" {
		t.Errorf("expected pg1 to be postgres, got %s", result["pg1"])
	}
	if result["cass1"] != "cassandra" {
		t.Errorf("expected cass1 to be cassandra, got %s", result["cass1"])
	}
}

func TestRegistry_Count(t *testing.T) {
	registry := NewRegistry()

	if registry.Count() != 0 {
		t.Error("expected count 0 for empty registry")
	}

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg1", &mockConnector{name: "pg1", connType: "postgres"}, config)

	if registry.Count() != 1 {
		t.Errorf("expected count 1, got %d", registry.Count())
	}
}

func TestRegistry_HealthCheck(t *testing.T) {
	registry := NewRegistry()

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg1", &mockConnector{name: "pg1", connType: "postgres", healthy: true}, config)
	config2 := &base.ConnectorConfig{Name: "pg2", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg2", &mockConnector{name: "pg2", connType: "postgres", healthy: false}, config2)

	ctx := context.Background()
	results := registry.HealthCheck(ctx)

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	if !results["pg1"].Healthy {
		t.Error("expected pg1 to be healthy")
	}
	if results["pg2"].Healthy {
		t.Error("expected pg2 to be unhealthy")
	}
}

func TestRegistry_HealthCheck_Error(t *testing.T) {
	registry := NewRegistry()

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg1", &mockConnector{
		name:      "pg1",
		connType:  "postgres",
		healthErr: errors.New("health check failed"),
	}, config)

	ctx := context.Background()
	results := registry.HealthCheck(ctx)

	if results["pg1"].Healthy {
		t.Error("expected unhealthy status when health check errors")
	}
	if results["pg1"].Error == "" {
		t.Error("expected error message in health status")
	}
}

func TestRegistry_HealthCheckSingle(t *testing.T) {
	registry := NewRegistry()

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg1", &mockConnector{name: "pg1", connType: "postgres", healthy: true}, config)

	ctx := context.Background()
	status, err := registry.HealthCheckSingle(ctx, "pg1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Healthy {
		t.Error("expected healthy status")
	}
}

func TestRegistry_HealthCheckSingle_NotFound(t *testing.T) {
	registry := NewRegistry()

	ctx := context.Background()
	_, err := registry.HealthCheckSingle(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent connector")
	}
}

func TestRegistry_HealthCheckSingle_Error(t *testing.T) {
	registry := NewRegistry()

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	registry.Register("pg1", &mockConnector{
		name:      "pg1",
		connType:  "postgres",
		healthErr: errors.New("health check failed"),
	}, config)

	ctx := context.Background()
	status, err := registry.HealthCheckSingle(ctx, "pg1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status")
	}
}

func TestRegistry_DisconnectAll(t *testing.T) {
	registry := NewRegistry()

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	conn1 := &mockConnector{name: "pg1", connType: "postgres", healthy: true}
	registry.Register("pg1", conn1, config)

	config2 := &base.ConnectorConfig{Name: "pg2", Type: "postgres", Timeout: 5 * time.Second}
	conn2 := &mockConnector{name: "pg2", connType: "postgres", healthy: true}
	registry.Register("pg2", conn2, config2)

	ctx := context.Background()
	registry.DisconnectAll(ctx)

	if conn1.connected {
		t.Error("expected conn1 to be disconnected")
	}
	if conn2.connected {
		t.Error("expected conn2 to be disconnected")
	}
}

func TestRegistry_DisconnectAll_WithErrors(t *testing.T) {
	registry := NewRegistry()

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second}
	conn1 := &mockConnector{
		name:          "pg1",
		connType:      "postgres",
		healthy:       true,
		disconnectErr: errors.New("disconnect failed"),
	}
	registry.Register("pg1", conn1, config)

	ctx := context.Background()
	// Should not panic
	registry.DisconnectAll(ctx)
}

func TestRegistry_GetConnectorsByTenant(t *testing.T) {
	registry := NewRegistry()

	// Add connectors for different tenants
	config1 := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second, TenantID: "tenant1"}
	registry.Register("pg1", &mockConnector{name: "pg1", connType: "postgres"}, config1)

	config2 := &base.ConnectorConfig{Name: "pg2", Type: "postgres", Timeout: 5 * time.Second, TenantID: "tenant2"}
	registry.Register("pg2", &mockConnector{name: "pg2", connType: "postgres"}, config2)

	config3 := &base.ConnectorConfig{Name: "pg3", Type: "postgres", Timeout: 5 * time.Second, TenantID: "*"}
	registry.Register("pg3", &mockConnector{name: "pg3", connType: "postgres"}, config3)

	// Tenant1 should see pg1 and pg3
	names := registry.GetConnectorsByTenant("tenant1")
	if len(names) != 2 {
		t.Errorf("expected 2 connectors for tenant1, got %d", len(names))
	}

	// Tenant2 should see pg2 and pg3
	names = registry.GetConnectorsByTenant("tenant2")
	if len(names) != 2 {
		t.Errorf("expected 2 connectors for tenant2, got %d", len(names))
	}
}

func TestRegistry_ValidateTenantAccess(t *testing.T) {
	registry := NewRegistry()

	config := &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second, TenantID: "tenant1"}
	registry.Register("pg1", &mockConnector{name: "pg1", connType: "postgres"}, config)

	config2 := &base.ConnectorConfig{Name: "pg2", Type: "postgres", Timeout: 5 * time.Second, TenantID: "*"}
	registry.Register("pg2", &mockConnector{name: "pg2", connType: "postgres"}, config2)

	// Valid access
	err := registry.ValidateTenantAccess("pg1", "tenant1")
	if err != nil {
		t.Errorf("expected no error for valid tenant access: %v", err)
	}

	// Invalid access
	err = registry.ValidateTenantAccess("pg1", "tenant2")
	if err == nil {
		t.Error("expected error for invalid tenant access")
	}

	// Wildcard access
	err = registry.ValidateTenantAccess("pg2", "any-tenant")
	if err != nil {
		t.Errorf("expected no error for wildcard tenant: %v", err)
	}

	// Nonexistent connector
	err = registry.ValidateTenantAccess("nonexistent", "tenant1")
	if err == nil {
		t.Error("expected error for nonexistent connector")
	}
}

func TestRegistry_SetFactory(t *testing.T) {
	registry := NewRegistry()

	factory := func(connectorType string) (base.Connector, error) {
		return &mockConnector{connType: connectorType}, nil
	}

	registry.SetFactory(factory)

	if registry.factory == nil {
		t.Error("expected factory to be set")
	}
}

func TestRegistry_LazyLoad(t *testing.T) {
	registry := NewRegistry()

	// Set factory
	factory := func(connectorType string) (base.Connector, error) {
		return &mockConnector{connType: connectorType, healthy: true}, nil
	}
	registry.SetFactory(factory)

	// Manually add config without connector (simulating storage load)
	registry.configs["pg1"] = &base.ConnectorConfig{
		Name:    "pg1",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	// Get should lazy-load
	conn, err := registry.Get("pg1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Error("expected connector to be lazy-loaded")
	}
}

func TestRegistry_LazyLoad_FactoryError(t *testing.T) {
	registry := NewRegistry()

	// Set factory that returns error
	factory := func(connectorType string) (base.Connector, error) {
		return nil, errors.New("factory error")
	}
	registry.SetFactory(factory)

	// Add config
	registry.configs["pg1"] = &base.ConnectorConfig{
		Name:    "pg1",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	// Get should fail
	_, err := registry.Get("pg1")
	if err == nil {
		t.Error("expected error from factory")
	}
}

func TestRegistry_LazyLoad_ConnectError(t *testing.T) {
	registry := NewRegistry()

	// Set factory that returns connector with connect error
	factory := func(connectorType string) (base.Connector, error) {
		return &mockConnector{
			connType:   connectorType,
			connectErr: errors.New("connect failed"),
		}, nil
	}
	registry.SetFactory(factory)

	// Add config
	registry.configs["pg1"] = &base.ConnectorConfig{
		Name:    "pg1",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	// Get should fail
	_, err := registry.Get("pg1")
	if err == nil {
		t.Error("expected connect error")
	}
}

func TestRegistry_ReloadFromStorage_NoStorage(t *testing.T) {
	registry := NewRegistry()

	ctx := context.Background()
	err := registry.ReloadFromStorage(ctx)
	if err != nil {
		t.Errorf("expected no error with no storage: %v", err)
	}
}

func TestRegistry_StartPeriodicReload_NoStorage(t *testing.T) {
	registry := NewRegistry()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should not panic and return immediately
	registry.StartPeriodicReload(ctx, 100*time.Millisecond)
}
