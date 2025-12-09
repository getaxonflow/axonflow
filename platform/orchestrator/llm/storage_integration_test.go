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

package llm

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Integration tests for PostgresStorage
// These tests require DATABASE_URL to be set and the schema to be migrated

func getTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Check connection
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return db
}

func setTestOrgID(t *testing.T, db *sql.DB, orgID string) {
	t.Helper()

	_, err := db.Exec("SELECT set_config('app.current_org_id', $1, false)", orgID)
	if err != nil {
		t.Fatalf("Failed to set app.current_org_id: %v", err)
	}
}

func cleanupTestProvider(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	// Direct delete bypassing RLS for cleanup
	_, err := db.Exec("DELETE FROM llm_providers WHERE name = $1", name)
	if err != nil {
		t.Logf("Cleanup warning: failed to delete provider %s: %v", name, err)
	}
}

func TestPostgresStorage_Integration_SaveAndGetProvider(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_llm_" + timestamp
	providerName := "test-provider-" + timestamp

	setTestOrgID(t, db, tenantID)
	defer cleanupTestProvider(t, db, providerName)

	config := &ProviderConfig{
		Name:           providerName,
		Type:           ProviderTypeAnthropic,
		APIKey:         "test-api-key-123",
		Model:          "claude-sonnet-4-20250514",
		Enabled:        true,
		Priority:       100,
		Weight:         50,
		RateLimit:      1000,
		TimeoutSeconds: 60,
		Settings: map[string]any{
			"max_tokens": 4096,
			"temperature": 0.7,
		},
	}

	// Save provider
	err := storage.SaveProvider(ctx, config)
	if err != nil {
		t.Fatalf("SaveProvider failed: %v", err)
	}

	// Get provider back
	retrieved, err := storage.GetProvider(ctx, providerName)
	if err != nil {
		t.Fatalf("GetProvider failed: %v", err)
	}

	// Verify fields
	if retrieved.Name != config.Name {
		t.Errorf("Name = %q, want %q", retrieved.Name, config.Name)
	}
	if retrieved.Type != config.Type {
		t.Errorf("Type = %q, want %q", retrieved.Type, config.Type)
	}
	if retrieved.APIKey != config.APIKey {
		t.Errorf("APIKey = %q, want %q", retrieved.APIKey, config.APIKey)
	}
	if retrieved.Model != config.Model {
		t.Errorf("Model = %q, want %q", retrieved.Model, config.Model)
	}
	if retrieved.Enabled != config.Enabled {
		t.Errorf("Enabled = %v, want %v", retrieved.Enabled, config.Enabled)
	}
	if retrieved.Priority != config.Priority {
		t.Errorf("Priority = %d, want %d", retrieved.Priority, config.Priority)
	}
	if retrieved.Weight != config.Weight {
		t.Errorf("Weight = %d, want %d", retrieved.Weight, config.Weight)
	}
	if retrieved.RateLimit != config.RateLimit {
		t.Errorf("RateLimit = %d, want %d", retrieved.RateLimit, config.RateLimit)
	}
	if retrieved.TimeoutSeconds != config.TimeoutSeconds {
		t.Errorf("TimeoutSeconds = %d, want %d", retrieved.TimeoutSeconds, config.TimeoutSeconds)
	}

	// Verify settings
	if retrieved.Settings == nil {
		t.Error("Settings should not be nil")
	} else {
		if maxTokens, ok := retrieved.Settings["max_tokens"].(float64); !ok || maxTokens != 4096 {
			t.Errorf("Settings[max_tokens] = %v, want 4096", retrieved.Settings["max_tokens"])
		}
	}
}

func TestPostgresStorage_Integration_UpdateProvider(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_update_" + timestamp
	providerName := "update-provider-" + timestamp

	setTestOrgID(t, db, tenantID)
	defer cleanupTestProvider(t, db, providerName)

	// Initial config
	config := &ProviderConfig{
		Name:     providerName,
		Type:     ProviderTypeOpenAI,
		APIKey:   "initial-key",
		Model:    "gpt-4",
		Enabled:  true,
		Priority: 50,
	}

	err := storage.SaveProvider(ctx, config)
	if err != nil {
		t.Fatalf("SaveProvider (initial) failed: %v", err)
	}

	// Update config
	config.Model = "gpt-4-turbo"
	config.Priority = 100
	config.Settings = map[string]any{"temperature": 0.5}

	err = storage.SaveProvider(ctx, config)
	if err != nil {
		t.Fatalf("SaveProvider (update) failed: %v", err)
	}

	// Verify update
	retrieved, err := storage.GetProvider(ctx, providerName)
	if err != nil {
		t.Fatalf("GetProvider failed: %v", err)
	}

	if retrieved.Model != "gpt-4-turbo" {
		t.Errorf("Model = %q, want %q", retrieved.Model, "gpt-4-turbo")
	}
	if retrieved.Priority != 100 {
		t.Errorf("Priority = %d, want 100", retrieved.Priority)
	}
}

func TestPostgresStorage_Integration_DeleteProvider(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_delete_" + timestamp
	providerName := "delete-provider-" + timestamp

	setTestOrgID(t, db, tenantID)
	defer cleanupTestProvider(t, db, providerName)

	config := &ProviderConfig{
		Name:    providerName,
		Type:    ProviderTypeOllama,
		Enabled: true,
	}

	err := storage.SaveProvider(ctx, config)
	if err != nil {
		t.Fatalf("SaveProvider failed: %v", err)
	}

	// Delete
	err = storage.DeleteProvider(ctx, providerName)
	if err != nil {
		t.Fatalf("DeleteProvider failed: %v", err)
	}

	// Verify deleted
	_, err = storage.GetProvider(ctx, providerName)
	if err == nil {
		t.Error("Expected error getting deleted provider")
	}
}

func TestPostgresStorage_Integration_ListProviders(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_list_" + timestamp

	setTestOrgID(t, db, tenantID)

	providerNames := []string{
		"list-provider-a-" + timestamp,
		"list-provider-b-" + timestamp,
		"list-provider-c-" + timestamp,
	}
	defer func() {
		for _, name := range providerNames {
			cleanupTestProvider(t, db, name)
		}
	}()

	// Create providers
	for _, name := range providerNames {
		config := &ProviderConfig{
			Name:    name,
			Type:    ProviderTypeAnthropic,
			Enabled: true,
		}
		if err := storage.SaveProvider(ctx, config); err != nil {
			t.Fatalf("SaveProvider for %s failed: %v", name, err)
		}
	}

	// List by tenant
	names, err := storage.ListProviders(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}

	if len(names) < 3 {
		t.Errorf("ListProviders returned %d names, want at least 3", len(names))
	}

	// Verify our providers are in the list
	foundCount := 0
	for _, name := range names {
		for _, pName := range providerNames {
			if name == pName {
				foundCount++
			}
		}
	}
	if foundCount != 3 {
		t.Errorf("Found %d test providers, want 3", foundCount)
	}

	// List all (uses RLS)
	allNames, err := storage.ListAllProviders(ctx)
	if err != nil {
		t.Fatalf("ListAllProviders failed: %v", err)
	}

	if len(allNames) < 3 {
		t.Errorf("ListAllProviders returned %d names, want at least 3", len(allNames))
	}
}

func TestPostgresStorage_Integration_GetNonexistent(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	setTestOrgID(t, db, "test_tenant_nonexistent")

	_, err := storage.GetProvider(ctx, "nonexistent-provider-12345")
	if err == nil {
		t.Error("Expected error for nonexistent provider")
	}
}

func TestPostgresStorage_Integration_DeleteNonexistent(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	setTestOrgID(t, db, "test_tenant_delete_nonexistent")

	err := storage.DeleteProvider(ctx, "nonexistent-provider-12345")
	if err == nil {
		t.Error("Expected error for deleting nonexistent provider")
	}
}

func TestPostgresStorage_Integration_SaveHealth(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_health_" + timestamp
	providerName := "health-provider-" + timestamp

	setTestOrgID(t, db, tenantID)
	defer cleanupTestProvider(t, db, providerName)

	// Create provider first
	config := &ProviderConfig{
		Name:    providerName,
		Type:    ProviderTypeAnthropic,
		Enabled: true,
	}
	if err := storage.SaveProvider(ctx, config); err != nil {
		t.Fatalf("SaveProvider failed: %v", err)
	}

	// Save health status
	healthResult := &HealthCheckResult{
		Status:              HealthStatusHealthy,
		Latency:             150 * time.Millisecond,
		Message:             "OK",
		LastChecked:         time.Now(),
		ConsecutiveFailures: 0,
	}

	err := storage.SaveHealth(ctx, providerName, healthResult)
	if err != nil {
		t.Fatalf("SaveHealth failed: %v", err)
	}

	// Update to unhealthy
	healthResult.Status = HealthStatusUnhealthy
	healthResult.Message = "Connection timeout"
	healthResult.ConsecutiveFailures = 3

	err = storage.SaveHealth(ctx, providerName, healthResult)
	if err != nil {
		t.Fatalf("SaveHealth (update) failed: %v", err)
	}
}

func TestPostgresStorage_Integration_RecordUsage(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_usage_" + timestamp
	providerName := "usage-provider-" + timestamp

	setTestOrgID(t, db, tenantID)
	defer cleanupTestProvider(t, db, providerName)

	// Create provider first
	config := &ProviderConfig{
		Name:    providerName,
		Type:    ProviderTypeAnthropic,
		Enabled: true,
	}
	if err := storage.SaveProvider(ctx, config); err != nil {
		t.Fatalf("SaveProvider failed: %v", err)
	}

	// Record usage
	usage := &ProviderUsage{
		ProviderName:     providerName,
		RequestID:        "req-" + timestamp,
		Model:            "claude-sonnet-4-20250514",
		InputTokens:      1000,
		OutputTokens:     500,
		TotalTokens:      1500,
		EstimatedCostUSD: 0.015,
		LatencyMs:        250,
		Status:           "success",
	}

	err := storage.RecordUsage(ctx, usage)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Record error usage
	errorUsage := &ProviderUsage{
		ProviderName: providerName,
		RequestID:    "req-error-" + timestamp,
		Model:        "claude-sonnet-4-20250514",
		LatencyMs:    5000,
		Status:       "timeout",
		ErrorMessage: "request timed out after 5s",
	}

	err = storage.RecordUsage(ctx, errorUsage)
	if err != nil {
		t.Fatalf("RecordUsage (error) failed: %v", err)
	}
}

func TestPostgresStorage_Integration_AllProviderTypes(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	storage := NewPostgresStorage(db)
	ctx := context.Background()

	timestamp := time.Now().Format("20060102150405")
	tenantID := "test_tenant_types_" + timestamp

	setTestOrgID(t, db, tenantID)

	types := []ProviderType{
		ProviderTypeOpenAI,
		ProviderTypeAnthropic,
		ProviderTypeBedrock,
		ProviderTypeOllama,
		ProviderTypeGemini,
		ProviderTypeCustom,
	}

	for _, pt := range types {
		providerName := "type-test-" + string(pt) + "-" + timestamp
		defer cleanupTestProvider(t, db, providerName)

		config := &ProviderConfig{
			Name:    providerName,
			Type:    pt,
			Enabled: true,
		}

		err := storage.SaveProvider(ctx, config)
		if err != nil {
			t.Errorf("SaveProvider for type %s failed: %v", pt, err)
			continue
		}

		retrieved, err := storage.GetProvider(ctx, providerName)
		if err != nil {
			t.Errorf("GetProvider for type %s failed: %v", pt, err)
			continue
		}

		if retrieved.Type != pt {
			t.Errorf("Type = %q, want %q", retrieved.Type, pt)
		}
	}
}
