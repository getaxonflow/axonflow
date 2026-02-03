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

package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
)

// Integration tests for connector marketplace handlers with real PostgreSQL database
// These tests require DATABASE_URL to be set

func TestConnectorMarketplace_InitializeConnectorRegistry_WithDatabase(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Set DATABASE_URL temporarily
	originalEnvURL := os.Getenv("DATABASE_URL")
	defer func() { _ = os.Setenv("DATABASE_URL", originalEnvURL) }()

	_ = os.Setenv("DATABASE_URL", dbURL)

	// Initialize registry with database
	initializeConnectorRegistry()

	if connectorRegistry == nil {
		t.Fatal("Registry should be initialized")
	}

	// Verify it's using database storage (not in-memory)
	// In-memory registry starts empty, DB registry may have persisted connectors
	connectors := connectorRegistry.ListWithTypes()

	// Just verify registry is functional, don't assume it's empty
	t.Logf("Registry initialized with %d persisted connectors", len(connectors))
}

func TestConnectorMarketplace_InitializeConnectorRegistry_WithInvalidDB(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Set invalid DATABASE_URL
	originalEnvURL := os.Getenv("DATABASE_URL")
	defer func() { _ = os.Setenv("DATABASE_URL", originalEnvURL) }()

	_ = os.Setenv("DATABASE_URL", "postgresql://invalid:invalid@nonexistent:5432/invalid")

	// Should fall back to in-memory registry
	initializeConnectorRegistry()

	if connectorRegistry == nil {
		t.Fatal("Registry should be initialized (fallback to in-memory)")
	}

	// In-memory registry should start empty
	connectors := connectorRegistry.ListWithTypes()
	if len(connectors) != 0 {
		t.Errorf("In-memory fallback registry should start empty, got %d connectors", len(connectors))
	}
}

func TestConnectorMarketplace_ConnectorPersistence_Install(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with database storage
	var err error
	connectorRegistry, err = registry.NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("Failed to create registry with storage: %v", err)
	}

	// Set factory for connector creation
	connectorRegistry.SetFactory(createConnectorInstance)

	// Generate unique connector ID for this test
	testConnectorID := "test-http-integration-" + time.Now().Format("20060102-150405")

	// Clean up test connector after test
	defer func() {
		_ = connectorRegistry.Unregister(testConnectorID)
	}()

	// Create and register HTTP connector
	connector, err := createConnectorInstance("http")
	if err != nil {
		t.Fatalf("Failed to create HTTP connector: %v", err)
	}

	config := &base.ConnectorConfig{
		Name:     "Test HTTP Connector",
		Type:     "http",
		TenantID: "test-tenant-integration",
		Options: map[string]interface{}{
			"base_url":          mockServer.URL,
			"allow_private_ips": true,
		},
		Timeout: 30 * time.Second,
	}

	// Register connector (should persist to database)
	err = connectorRegistry.Register(testConnectorID, connector, config)
	if err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	// Verify connector is registered
	connectors := connectorRegistry.ListWithTypes()
	if _, exists := connectors[testConnectorID]; !exists {
		t.Error("Connector should be registered in memory")
	}

	// Create a NEW registry instance to verify persistence
	newRegistry, err := registry.NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("Failed to create new registry: %v", err)
	}
	newRegistry.SetFactory(createConnectorInstance)

	// Reload connectors from database
	ctx := context.Background()
	reloadErr := newRegistry.ReloadFromStorage(ctx)
	if reloadErr != nil {
		t.Fatalf("Failed to reload from database: %v", reloadErr)
	}

	// Verify connector was persisted and reloaded
	// After ReloadFromStorage, connectors are lazy-loaded (stored in configs but not
	// instantiated). Use GetConfig to check persistence rather than ListWithTypes
	// which only returns instantiated connectors.
	if _, err := newRegistry.GetConfig(testConnectorID); err != nil {
		t.Error("Connector should be persisted in database and reloaded")
	}
}

func TestConnectorMarketplace_ConnectorPersistence_Uninstall(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with database storage
	var err error
	connectorRegistry, err = registry.NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("Failed to create registry with storage: %v", err)
	}

	connectorRegistry.SetFactory(createConnectorInstance)

	// Generate unique connector ID for this test
	testConnectorID := "test-http-uninstall-" + time.Now().Format("20060102-150405")

	// Clean up test connector after test (in case uninstall fails)
	defer func() {
		_ = connectorRegistry.Unregister(testConnectorID)
	}()

	// Create and register HTTP connector
	connector, err := createConnectorInstance("http")
	if err != nil {
		t.Fatalf("Failed to create HTTP connector: %v", err)
	}

	config := &base.ConnectorConfig{
		Name:     "Test HTTP Connector Uninstall",
		Type:     "http",
		TenantID: "test-tenant-integration",
		Options: map[string]interface{}{
			"base_url":          mockServer.URL,
			"allow_private_ips": true,
		},
		Timeout: 30 * time.Second,
	}

	// Register connector
	err = connectorRegistry.Register(testConnectorID, connector, config)
	if err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	// Verify connector exists
	connectors := connectorRegistry.ListWithTypes()
	if _, exists := connectors[testConnectorID]; !exists {
		t.Fatal("Connector should be registered")
	}

	// Uninstall connector (should delete from database)
	err = connectorRegistry.Unregister(testConnectorID)
	if err != nil {
		t.Fatalf("Failed to unregister connector: %v", err)
	}

	// Verify connector is removed from memory
	connectors = connectorRegistry.ListWithTypes()
	if _, exists := connectors[testConnectorID]; exists {
		t.Error("Connector should be unregistered from memory")
	}

	// Create a NEW registry instance to verify deletion from database
	newRegistry, err := registry.NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("Failed to create new registry: %v", err)
	}
	newRegistry.SetFactory(createConnectorInstance)

	// Reload connectors from database
	ctx := context.Background()
	reloadErr := newRegistry.ReloadFromStorage(ctx)
	if reloadErr != nil {
		t.Fatalf("Failed to reload from database: %v", reloadErr)
	}

	// Verify connector was deleted from database
	// Use GetConfig (checks configs map) for consistency with lazy-loading behavior
	if _, err := newRegistry.GetConfig(testConnectorID); err == nil {
		t.Error("Connector should be deleted from database")
	}
}

func TestConnectorMarketplace_PeriodicReload_Mechanism(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with database storage
	var err error
	connectorRegistry, err = registry.NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("Failed to create registry with storage: %v", err)
	}

	connectorRegistry.SetFactory(createConnectorInstance)

	// Start periodic reload with short interval for testing
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start reload with 1 second interval (much shorter than production 30s)
	go connectorRegistry.StartPeriodicReload(ctx, 1*time.Second)

	// Wait a bit to ensure reload mechanism starts
	time.Sleep(100 * time.Millisecond)

	// Register a test connector in a separate registry instance to simulate another orchestrator
	testConnectorID := "test-http-reload-" + time.Now().Format("20060102-150405")

	// Clean up test connector after test
	defer func() {
		_ = connectorRegistry.Unregister(testConnectorID)
	}()

	// Create a second registry to simulate another orchestrator instance
	otherRegistry, err := registry.NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("Failed to create second registry: %v", err)
	}
	otherRegistry.SetFactory(createConnectorInstance)

	// Register connector in the OTHER registry (simulating another orchestrator)
	connector, err := createConnectorInstance("http")
	if err != nil {
		t.Fatalf("Failed to create connector: %v", err)
	}

	config := &base.ConnectorConfig{
		Name:     "Test Reload Connector",
		Type:     "http",
		TenantID: "test-tenant-reload",
		Options: map[string]interface{}{
			"base_url":          mockServer.URL,
			"allow_private_ips": true,
		},
		Timeout: 30 * time.Second,
	}

	err = otherRegistry.Register(testConnectorID, connector, config)
	if err != nil {
		t.Fatalf("Failed to register connector in other registry: %v", err)
	}

	// Wait for periodic reload to pick up the new connector (max 2 seconds)
	// Use GetConfig since ReloadFromStorage lazy-loads configs without instantiation
	found := false
	for i := 0; i < 4; i++ {
		time.Sleep(600 * time.Millisecond)
		if _, err := connectorRegistry.GetConfig(testConnectorID); err == nil {
			found = true
			break
		}
	}

	if !found {
		t.Error("Periodic reload should have picked up connector registered in other instance")
	}

	// Cancel context to stop periodic reload
	cancel()
	time.Sleep(100 * time.Millisecond) // Give goroutine time to exit
}
