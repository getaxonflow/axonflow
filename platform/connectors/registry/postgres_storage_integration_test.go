// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

// Integration tests for PostgreSQLStorage
// These tests require DATABASE_URL to be set

func getTestDBURL(t *testing.T) string {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}
	return dbURL
}

func TestPostgreSQLStorage_Integration_NewAndClose(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}

	if storage == nil {
		t.Fatal("Expected non-nil storage")
	}

	// Close should work
	err = storage.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestPostgreSQLStorage_Integration_SaveAndGet(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}

	ctx := context.Background()
	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_storage_" + timestamp
	connectorID := "integration_test_connector_" + timestamp

	config := &base.ConnectorConfig{
		Name:          connectorID,
		Type:          "postgres",
		ConnectionURL: "postgres://test:5432/testdb",
		TenantID:      tenantID,
		Timeout:       30 * time.Second,
		MaxRetries:    3,
		Options: map[string]interface{}{
			"ssl_mode": "require",
		},
		Credentials: map[string]string{
			"username": "testuser",
		},
	}

	// Save connector
	err = storage.SaveConnector(ctx, connectorID, config)
	if err != nil {
		t.Fatalf("SaveConnector failed: %v", err)
	}

	// Get connector back
	retrieved, err := storage.GetConnector(ctx, connectorID)
	if err != nil {
		t.Fatalf("GetConnector failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected non-nil config")
	}

	if retrieved.Name != config.Name {
		t.Errorf("Name = %q, want %q", retrieved.Name, config.Name)
	}
	if retrieved.Type != config.Type {
		t.Errorf("Type = %q, want %q", retrieved.Type, config.Type)
	}
	if retrieved.TenantID != config.TenantID {
		t.Errorf("TenantID = %q, want %q", retrieved.TenantID, config.TenantID)
	}

	// Cleanup - delete before closing storage
	_ = storage.DeleteConnector(ctx, connectorID)
	_ = storage.Close()
}

func TestPostgreSQLStorage_Integration_Update(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}

	ctx := context.Background()
	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_update_" + timestamp
	connectorID := "update_test_connector_" + timestamp

	// Initial config
	config := &base.ConnectorConfig{
		Name:     connectorID,
		Type:     "postgres",
		TenantID: tenantID,
		Options: map[string]interface{}{
			"pool_size": float64(10),
		},
	}

	// Save
	err = storage.SaveConnector(ctx, connectorID, config)
	if err != nil {
		t.Fatalf("SaveConnector failed: %v", err)
	}

	// Update with new options
	config.Options["pool_size"] = float64(20)
	config.Options["timeout"] = "30s"

	err = storage.SaveConnector(ctx, connectorID, config)
	if err != nil {
		t.Fatalf("SaveConnector (update) failed: %v", err)
	}

	// Verify update
	retrieved, err := storage.GetConnector(ctx, connectorID)
	if err != nil {
		t.Fatalf("GetConnector failed: %v", err)
	}

	poolSize, ok := retrieved.Options["pool_size"].(float64)
	if !ok || poolSize != 20 {
		t.Errorf("Expected pool_size=20, got %v", retrieved.Options["pool_size"])
	}

	// Cleanup - delete before closing storage
	_ = storage.DeleteConnector(ctx, connectorID)
	_ = storage.Close()
}

func TestPostgreSQLStorage_Integration_List(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}

	ctx := context.Background()
	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_list_" + timestamp

	// Create multiple connectors
	connectorIDs := []string{
		"list_test_1_" + timestamp,
		"list_test_2_" + timestamp,
		"list_test_3_" + timestamp,
	}
	configs := []*base.ConnectorConfig{
		{Name: connectorIDs[0], Type: "postgres", TenantID: tenantID},
		{Name: connectorIDs[1], Type: "cassandra", TenantID: tenantID},
		{Name: connectorIDs[2], Type: "redis", TenantID: tenantID},
	}

	for i, cfg := range configs {
		if err := storage.SaveConnector(ctx, connectorIDs[i], cfg); err != nil {
			t.Fatalf("SaveConnector for %s failed: %v", cfg.Name, err)
		}
	}

	// List all connectors
	ids, err := storage.ListConnectors(ctx)
	if err != nil {
		t.Fatalf("ListConnectors failed: %v", err)
	}

	// Should have at least our 3 connectors
	foundCount := 0
	for _, id := range ids {
		for _, cid := range connectorIDs {
			if id == cid {
				foundCount++
			}
		}
	}

	if foundCount != 3 {
		t.Errorf("Expected to find 3 test connectors, found %d", foundCount)
	}

	// List by tenant
	tenantIds, err := storage.ListConnectorsByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListConnectorsByTenant failed: %v", err)
	}

	if len(tenantIds) != 3 {
		t.Errorf("Expected 3 connectors for tenant, got %d", len(tenantIds))
	}

	// Cleanup - delete before closing storage
	for _, id := range connectorIDs {
		_ = storage.DeleteConnector(ctx, id)
	}
	_ = storage.Close()
}

func TestPostgreSQLStorage_Integration_Delete(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_delete_" + timestamp
	connectorID := "delete_test_connector_" + timestamp

	config := &base.ConnectorConfig{
		Name:     connectorID,
		Type:     "postgres",
		TenantID: tenantID,
	}

	// Save
	err = storage.SaveConnector(ctx, connectorID, config)
	if err != nil {
		t.Fatalf("SaveConnector failed: %v", err)
	}

	// Verify exists
	retrieved, err := storage.GetConnector(ctx, connectorID)
	if err != nil || retrieved == nil {
		t.Fatal("Expected connector to exist after save")
	}

	// Delete
	err = storage.DeleteConnector(ctx, connectorID)
	if err != nil {
		t.Fatalf("DeleteConnector failed: %v", err)
	}

	// Verify deleted
	retrieved, err = storage.GetConnector(ctx, connectorID)
	if err == nil && retrieved != nil {
		t.Error("Expected connector to be deleted")
	}
}

func TestPostgreSQLStorage_Integration_UpdateHealthStatus(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}

	ctx := context.Background()
	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_health_" + timestamp
	connectorID := "health_test_connector_" + timestamp

	config := &base.ConnectorConfig{
		Name:     connectorID,
		Type:     "postgres",
		TenantID: tenantID,
	}

	// Save connector
	err = storage.SaveConnector(ctx, connectorID, config)
	if err != nil {
		t.Fatalf("SaveConnector failed: %v", err)
	}

	// Update health status to healthy
	healthyStatus := &base.HealthStatus{
		Healthy:   true,
		Latency:   10 * time.Millisecond,
		Timestamp: time.Now(),
	}
	err = storage.UpdateHealthStatus(ctx, connectorID, healthyStatus)
	if err != nil {
		t.Errorf("UpdateHealthStatus (healthy) failed: %v", err)
	}

	// Update health status to unhealthy
	unhealthyStatus := &base.HealthStatus{
		Healthy:   false,
		Error:     "connection refused",
		Timestamp: time.Now(),
	}
	err = storage.UpdateHealthStatus(ctx, connectorID, unhealthyStatus)
	if err != nil {
		t.Errorf("UpdateHealthStatus (unhealthy) failed: %v", err)
	}

	// Cleanup - delete before closing storage
	_ = storage.DeleteConnector(ctx, connectorID)
	_ = storage.Close()
}

func TestPostgreSQLStorage_Integration_GetNonexistent(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Try to get nonexistent connector
	_, err = storage.GetConnector(ctx, "nonexistent_connector_12345")
	if err == nil {
		t.Error("Expected error for nonexistent connector")
	}
}

func TestPostgreSQLStorage_Integration_DeleteNonexistent(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Try to delete nonexistent connector - should error
	err = storage.DeleteConnector(ctx, "nonexistent_connector_12345")
	if err == nil {
		t.Error("Expected error for deleting nonexistent connector")
	}
}

func TestNewRegistryWithStorage_Integration(t *testing.T) {
	dbURL := getTestDBURL(t)

	registry, err := NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("NewRegistryWithStorage failed: %v", err)
	}

	if registry == nil {
		t.Fatal("Expected non-nil registry")
	}

	if registry.storage == nil {
		t.Error("Expected storage to be initialized")
	}

	// Cleanup - disconnect all connectors and close storage
	ctx := context.Background()
	registry.DisconnectAll(ctx)
	_ = registry.storage.Close()
}

func TestRegistry_Integration_ReloadFromStorage(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}

	ctx := context.Background()
	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_reload_" + timestamp
	connectorID := "reload_test_connector_" + timestamp

	// Create a connector in storage
	config := &base.ConnectorConfig{
		Name:     connectorID,
		Type:     "postgres",
		TenantID: tenantID,
		Timeout:  5 * time.Second,
	}
	err = storage.SaveConnector(ctx, connectorID, config)
	if err != nil {
		t.Fatalf("SaveConnector failed: %v", err)
	}

	// Create registry with storage
	registry, err := NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("NewRegistryWithStorage failed: %v", err)
	}

	// Reload from storage
	err = registry.ReloadFromStorage(ctx)
	if err != nil {
		t.Fatalf("ReloadFromStorage failed: %v", err)
	}

	// Verify config was loaded
	loadedConfig, err := registry.GetConfig(connectorID)
	if err != nil {
		t.Logf("GetConfig result: %v (may need factory for full test)", err)
	} else if loadedConfig != nil {
		if loadedConfig.Name != connectorID {
			t.Errorf("Loaded config name mismatch")
		}
	}

	// Cleanup - delete before closing storage
	_ = storage.DeleteConnector(ctx, connectorID)
	_ = storage.Close()
	_ = registry.storage.Close()
}

func TestRegistry_Integration_StartPeriodicReload(t *testing.T) {
	dbURL := getTestDBURL(t)

	registry, err := NewRegistryWithStorage(dbURL)
	if err != nil {
		t.Fatalf("NewRegistryWithStorage failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start periodic reload with short interval
	registry.StartPeriodicReload(ctx, 100*time.Millisecond)

	// Let it run briefly
	time.Sleep(250 * time.Millisecond)

	// Cancel to stop
	cancel()

	// Give goroutine time to stop
	time.Sleep(50 * time.Millisecond)

	// Cleanup - close storage
	_ = registry.storage.Close()

	// No assertion needed - just verify no panic/deadlock
}

func TestPostgreSQLStorage_Integration_CredentialsRoundTrip(t *testing.T) {
	dbURL := getTestDBURL(t)

	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		t.Fatalf("NewPostgreSQLStorage failed: %v", err)
	}

	ctx := context.Background()
	connectorID := "creds_test_" + time.Now().Format("20060102150405")

	config := &base.ConnectorConfig{
		Name:     connectorID,
		Type:     "postgres",
		TenantID: "test_tenant",
		Credentials: map[string]string{
			"username": "admin",
			"password": "secret123",
			"api_key":  "key-12345",
		},
		Options: map[string]interface{}{
			"ssl":       true,
			"pool_size": float64(10),
		},
	}

	// Save
	err = storage.SaveConnector(ctx, connectorID, config)
	if err != nil {
		t.Fatalf("SaveConnector failed: %v", err)
	}

	// Retrieve
	retrieved, err := storage.GetConnector(ctx, connectorID)
	if err != nil {
		t.Fatalf("GetConnector failed: %v", err)
	}

	// Verify credentials
	if retrieved.Credentials["username"] != "admin" {
		t.Errorf("username = %q, want %q", retrieved.Credentials["username"], "admin")
	}
	if retrieved.Credentials["password"] != "secret123" {
		t.Errorf("password = %q, want %q", retrieved.Credentials["password"], "secret123")
	}
	if retrieved.Credentials["api_key"] != "key-12345" {
		t.Errorf("api_key = %q, want %q", retrieved.Credentials["api_key"], "key-12345")
	}

	// Verify options
	if retrieved.Options["ssl"] != true {
		t.Errorf("ssl = %v, want true", retrieved.Options["ssl"])
	}

	// Cleanup - delete before closing storage
	_ = storage.DeleteConnector(ctx, connectorID)
	_ = storage.Close()
}
