// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Integration tests for RegistryRepository
// These tests require DATABASE_URL to be set

func getTestDB(t *testing.T) *sql.DB {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return db
}

func getOrCreateTestOrg(t *testing.T, db *sql.DB, orgID string) string {
	// Check if org exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM organizations WHERE org_id = $1)", orgID).Scan(&exists)
	if err != nil {
		t.Fatalf("Failed to check org existence: %v", err)
	}

	if !exists {
		_, err = db.Exec(`
			INSERT INTO organizations (org_id, name, tier, license_key, created_at, updated_at)
			VALUES ($1, $2, 'enterprise', 'test-license-key', NOW(), NOW())
			ON CONFLICT (org_id) DO NOTHING`,
			orgID, "test-org-"+orgID)
		if err != nil {
			t.Fatalf("Failed to create test org: %v", err)
		}
	}

	return orgID
}

func cleanupTestRegistryData(t *testing.T, db *sql.DB, orgID string) {
	// Clean up in order due to foreign key constraints
	_, err := db.Exec("DELETE FROM mas_kill_switch_history WHERE kill_switch_id IN (SELECT id FROM mas_kill_switches WHERE org_id = $1)", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup kill switch history: %v", err)
	}
	_, err = db.Exec("DELETE FROM mas_kill_switches WHERE org_id = $1", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup kill switches: %v", err)
	}
	_, err = db.Exec("DELETE FROM mas_feat_assessments WHERE org_id = $1", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup assessments: %v", err)
	}
	_, err = db.Exec("DELETE FROM mas_ai_system_registry WHERE org_id = $1", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup registry: %v", err)
	}
}

func TestRegistryRepository_Integration_NewPostgresRegistryRepository(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected repository to have the provided database connection")
	}
}

func TestRegistryRepository_Integration_Create(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-create-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	deployDate := time.Now().UTC().AddDate(0, -1, 0)
	system := &AISystemRegistry{
		OrgID:               orgID,
		SystemID:            "sys-" + uuid.New().String()[:8],
		SystemName:          "Test AI System",
		Description:         "A test AI system for integration testing",
		UseCase:             UseCaseCustomerService,
		Status:              SystemStatusActive,
		RiskRatingImpact:    4,
		RiskRatingComplexity: 3,
		RiskRatingReliance:  5,
		OwnerTeam:           "ML Team",
		OwnerEmail:          "ml-team@example.com",
		ModelType:           "llm",
		Version:             "1.0.0",
		DeploymentDate:      &deployDate,
		DataSources:         []string{"customer_data", "product_catalog"},
		Metadata:            map[string]interface{}{"environment": "production"},
		CreatedBy:           "test-user",
	}

	err := repo.Create(ctx, system)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if system.ID == "" {
		t.Error("Expected ID to be generated")
	}
	if system.MaterialityClassification == "" {
		t.Error("Expected MaterialityClassification to be calculated")
	}

	// Verify by retrieving
	retrieved, err := repo.GetByID(ctx, orgID, system.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected system to be found")
	}
	if retrieved.SystemName != "Test AI System" {
		t.Errorf("Expected SystemName 'Test AI System', got %s", retrieved.SystemName)
	}
	if retrieved.UseCase != "customer_service" {
		t.Errorf("Expected UseCase 'customer_service', got %s", retrieved.UseCase)
	}
	if retrieved.Status != SystemStatusActive {
		t.Errorf("Expected Status 'active', got %s", retrieved.Status)
	}
	if retrieved.RiskRatingImpact != 4 {
		t.Errorf("Expected RiskRatingImpact 4, got %d", retrieved.RiskRatingImpact)
	}
}

func TestRegistryRepository_Integration_Create_MaterialityCalculation(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-mat-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	tests := []struct {
		name      string
		impact    int
		complex   int
		reliance  int
		wantClass MaterialityClassification
	}{
		{"high materiality", 5, 4, 4, MaterialityHigh},    // sum = 13
		{"medium materiality", 3, 3, 3, MaterialityMedium}, // sum = 9
		{"low materiality", 2, 2, 2, MaterialityLow},       // sum = 6
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			system := &AISystemRegistry{
				OrgID:               orgID,
				SystemID:            "sys-mat-" + uuid.New().String()[:8],
				SystemName:          "Materiality Test System",
				UseCase:             UseCaseOther,
				Status:              SystemStatusActive,
				RiskRatingImpact:    tt.impact,
				RiskRatingComplexity: tt.complex,
				RiskRatingReliance:  tt.reliance,
				OwnerTeam:           "Test Team",
				OwnerEmail:          "test@example.com",
				CreatedBy:           "test-user",
			}

			err := repo.Create(ctx, system)
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}

			retrieved, err := repo.GetByID(ctx, orgID, system.ID)
			if err != nil {
				t.Fatalf("GetByID() error = %v", err)
			}

			if retrieved.MaterialityClassification != tt.wantClass {
				t.Errorf("Expected MaterialityClassification %s, got %s", tt.wantClass, retrieved.MaterialityClassification)
			}
		})
	}
}

func TestRegistryRepository_Integration_GetByID_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-notfound-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	retrieved, err := repo.GetByID(ctx, orgID, "non-existent-id")
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for non-existent ID")
	}
}

func TestRegistryRepository_Integration_GetBySystemID(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-sysid-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	systemID := "unique-sys-" + uuid.New().String()[:8]
	system := &AISystemRegistry{
		OrgID:               orgID,
		SystemID:            systemID,
		SystemName:          "System ID Test",
		UseCase:             UseCaseOther,
		Status:              SystemStatusActive,
		RiskRatingImpact:    3,
		RiskRatingComplexity: 3,
		RiskRatingReliance:  3,
		OwnerTeam:           "Test Team",
		OwnerEmail:          "test@example.com",
		CreatedBy:           "test-user",
	}

	if err := repo.Create(ctx, system); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Retrieve by system ID
	retrieved, err := repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected system to be found")
	}
	if retrieved.SystemID != systemID {
		t.Errorf("Expected SystemID %s, got %s", systemID, retrieved.SystemID)
	}
}

func TestRegistryRepository_Integration_GetBySystemID_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-sysid-nf-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	retrieved, err := repo.GetBySystemID(ctx, orgID, "non-existent-system-id")
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for non-existent system ID")
	}
}

func TestRegistryRepository_Integration_List(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-list-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create multiple systems
	for i := 0; i < 5; i++ {
		system := &AISystemRegistry{
			OrgID:               orgID,
			SystemID:            "sys-list-" + uuid.New().String()[:8],
			SystemName:          "List Test System " + string(rune('A'+i)),
			UseCase:             UseCaseOther,
			Status:              SystemStatusActive,
			RiskRatingImpact:    3,
			RiskRatingComplexity: 3,
			RiskRatingReliance:  3,
			OwnerTeam:           "Test Team",
			OwnerEmail:          "test@example.com",
			CreatedBy:           "test-user",
		}
		if err := repo.Create(ctx, system); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		// Small delay to ensure distinct created_at times
		time.Sleep(10 * time.Millisecond)
	}

	// List all
	systems, err := repo.List(ctx, orgID, ListParams{Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(systems) != 5 {
		t.Errorf("Expected 5 systems, got %d", len(systems))
	}

	// Verify ordering (most recent first)
	if systems[0].SystemName != "List Test System E" {
		t.Errorf("Expected most recent system first, got %s", systems[0].SystemName)
	}
}

func TestRegistryRepository_Integration_List_WithStatusFilter(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-list-status-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create systems with different statuses
	statuses := []SystemStatus{SystemStatusActive, SystemStatusActive, SystemStatusSuspended, SystemStatusRetired}
	for i, status := range statuses {
		system := &AISystemRegistry{
			OrgID:               orgID,
			SystemID:            "sys-status-" + uuid.New().String()[:8],
			SystemName:          "Status Test " + string(rune('A'+i)),
			UseCase:             UseCaseOther,
			Status:              status,
			RiskRatingImpact:    3,
			RiskRatingComplexity: 3,
			RiskRatingReliance:  3,
			OwnerTeam:           "Test Team",
			OwnerEmail:          "test@example.com",
			CreatedBy:           "test-user",
		}
		if err := repo.Create(ctx, system); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Filter by active status
	activeSystems, err := repo.List(ctx, orgID, ListParams{Status: string(SystemStatusActive), Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(activeSystems) != 2 {
		t.Errorf("Expected 2 active systems, got %d", len(activeSystems))
	}
}

func TestRegistryRepository_Integration_List_Pagination(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-page-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create 7 systems
	for i := 0; i < 7; i++ {
		system := &AISystemRegistry{
			OrgID:               orgID,
			SystemID:            "sys-page-" + uuid.New().String()[:8],
			SystemName:          "Pagination Test " + string(rune('A'+i)),
			UseCase:             UseCaseOther,
			Status:              SystemStatusActive,
			RiskRatingImpact:    3,
			RiskRatingComplexity: 3,
			RiskRatingReliance:  3,
			OwnerTeam:           "Test Team",
			OwnerEmail:          "test@example.com",
			CreatedBy:           "test-user",
		}
		if err := repo.Create(ctx, system); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// First page
	page1, err := repo.List(ctx, orgID, ListParams{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page1) != 3 {
		t.Errorf("Expected 3 systems on page 1, got %d", len(page1))
	}

	// Second page
	page2, err := repo.List(ctx, orgID, ListParams{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page2) != 3 {
		t.Errorf("Expected 3 systems on page 2, got %d", len(page2))
	}

	// Third page (remaining 1)
	page3, err := repo.List(ctx, orgID, ListParams{Limit: 3, Offset: 6})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page3) != 1 {
		t.Errorf("Expected 1 system on page 3, got %d", len(page3))
	}
}

func TestRegistryRepository_Integration_Update(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-update-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a system
	system := &AISystemRegistry{
		OrgID:               orgID,
		SystemID:            "sys-update-" + uuid.New().String()[:8],
		SystemName:          "Original Name",
		UseCase:             UseCaseOther,
		Status:              SystemStatusActive,
		RiskRatingImpact:    3,
		RiskRatingComplexity: 3,
		RiskRatingReliance:  3,
		OwnerTeam:           "Original Team",
		OwnerEmail:          "original@example.com",
		CreatedBy:           "test-user",
	}
	if err := repo.Create(ctx, system); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update the system
	system.SystemName = "Updated Name"
	system.RiskRatingImpact = 5
	system.RiskRatingComplexity = 4
	system.RiskRatingReliance = 4
	system.UpdatedBy = "updater-user"

	err := repo.Update(ctx, system)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify update
	retrieved, err := repo.GetByID(ctx, orgID, system.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.SystemName != "Updated Name" {
		t.Errorf("Expected SystemName 'Updated Name', got %s", retrieved.SystemName)
	}
	if retrieved.RiskRatingImpact != 5 {
		t.Errorf("Expected RiskRatingImpact 5, got %d", retrieved.RiskRatingImpact)
	}
	// Materiality should be recalculated to high (5+4+4 = 13)
	if retrieved.MaterialityClassification != MaterialityHigh {
		t.Errorf("Expected MaterialityClassification 'high', got %s", retrieved.MaterialityClassification)
	}
	if retrieved.UpdatedBy != "updater-user" {
		t.Errorf("Expected UpdatedBy 'updater-user', got %s", retrieved.UpdatedBy)
	}
}

func TestRegistryRepository_Integration_Delete(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-delete-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a system
	system := &AISystemRegistry{
		OrgID:               orgID,
		SystemID:            "sys-delete-" + uuid.New().String()[:8],
		SystemName:          "To Be Deleted",
		UseCase:             UseCaseOther,
		Status:              SystemStatusActive,
		RiskRatingImpact:    3,
		RiskRatingComplexity: 3,
		RiskRatingReliance:  3,
		OwnerTeam:           "Test Team",
		OwnerEmail:          "test@example.com",
		CreatedBy:           "test-user",
	}
	if err := repo.Create(ctx, system); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete (soft-delete)
	err := repo.Delete(ctx, orgID, system.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify status changed to retired
	retrieved, err := repo.GetByID(ctx, orgID, system.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected system to still exist (soft delete)")
	}
	if retrieved.Status != SystemStatusRetired {
		t.Errorf("Expected Status 'retired', got %s", retrieved.Status)
	}
}

func TestRegistryRepository_Integration_GetSummary(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-summary-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create systems with different statuses and materiality levels
	systems := []struct {
		status     SystemStatus
		impact     int
		complex    int
		reliance   int
	}{
		{SystemStatusActive, 5, 4, 4},     // high materiality
		{SystemStatusActive, 5, 5, 4},     // high materiality
		{SystemStatusActive, 3, 3, 3},     // medium materiality
		{SystemStatusSuspended, 2, 2, 2}, // low materiality
		{SystemStatusRetired, 3, 3, 3},    // medium materiality (retired)
	}

	for i, s := range systems {
		system := &AISystemRegistry{
			OrgID:               orgID,
			SystemID:            "sys-sum-" + uuid.New().String()[:8],
			SystemName:          "Summary Test " + string(rune('A'+i)),
			UseCase:             UseCaseOther,
			Status:              s.status,
			RiskRatingImpact:    s.impact,
			RiskRatingComplexity: s.complex,
			RiskRatingReliance:  s.reliance,
			OwnerTeam:           "Test Team",
			OwnerEmail:          "test@example.com",
			CreatedBy:           "test-user",
		}
		if err := repo.Create(ctx, system); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Get summary
	summary, err := repo.GetSummary(ctx, orgID)
	if err != nil {
		t.Fatalf("GetSummary() error = %v", err)
	}

	if summary == nil {
		t.Fatal("Expected summary to be returned")
	}
	if summary.TotalSystems != 5 {
		t.Errorf("Expected TotalSystems 5, got %d", summary.TotalSystems)
	}
	if summary.ActiveSystems != 3 {
		t.Errorf("Expected ActiveSystems 3, got %d", summary.ActiveSystems)
	}
	if summary.HighMateriality != 2 {
		t.Errorf("Expected HighMateriality 2, got %d", summary.HighMateriality)
	}
	if summary.MediumMateriality != 2 {
		t.Errorf("Expected MediumMateriality 2, got %d", summary.MediumMateriality)
	}
	if summary.LowMateriality != 1 {
		t.Errorf("Expected LowMateriality 1, got %d", summary.LowMateriality)
	}
}

func TestRegistryRepository_Integration_CountByStatus(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-count-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create systems with different statuses
	statuses := []SystemStatus{
		SystemStatusActive, SystemStatusActive, SystemStatusActive,
		SystemStatusSuspended, SystemStatusSuspended,
		SystemStatusRetired,
	}

	for i, status := range statuses {
		system := &AISystemRegistry{
			OrgID:               orgID,
			SystemID:            "sys-count-" + uuid.New().String()[:8],
			SystemName:          "Count Test " + string(rune('A'+i)),
			UseCase:             UseCaseOther,
			Status:              status,
			RiskRatingImpact:    3,
			RiskRatingComplexity: 3,
			RiskRatingReliance:  3,
			OwnerTeam:           "Test Team",
			OwnerEmail:          "test@example.com",
			CreatedBy:           "test-user",
		}
		if err := repo.Create(ctx, system); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Get counts
	counts, err := repo.CountByStatus(ctx, orgID)
	if err != nil {
		t.Fatalf("CountByStatus() error = %v", err)
	}

	if counts[SystemStatusActive] != 3 {
		t.Errorf("Expected 3 active systems, got %d", counts[SystemStatusActive])
	}
	if counts[SystemStatusSuspended] != 2 {
		t.Errorf("Expected 2 under_review systems, got %d", counts[SystemStatusSuspended])
	}
	if counts[SystemStatusRetired] != 1 {
		t.Errorf("Expected 1 retired system, got %d", counts[SystemStatusRetired])
	}
}

func TestRegistryRepository_Integration_AllStatuses(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-all-status-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Test all valid system statuses
	statuses := []SystemStatus{
		SystemStatusActive,
		SystemStatusSuspended,
		SystemStatusRetired,
	}

	for _, status := range statuses {
		system := &AISystemRegistry{
			OrgID:               orgID,
			SystemID:            "sys-all-" + uuid.New().String()[:8],
			SystemName:          "Status " + string(status),
			UseCase:             UseCaseOther,
			Status:              status,
			RiskRatingImpact:    3,
			RiskRatingComplexity: 3,
			RiskRatingReliance:  3,
			OwnerTeam:           "Test Team",
			OwnerEmail:          "test@example.com",
			CreatedBy:           "test-user",
		}
		if err := repo.Create(ctx, system); err != nil {
			t.Fatalf("Create() error for status %s: %v", status, err)
		}

		retrieved, err := repo.GetByID(ctx, orgID, system.ID)
		if err != nil {
			t.Fatalf("GetByID() error for status %s: %v", status, err)
		}
		if retrieved.Status != status {
			t.Errorf("Expected Status %s, got %s", status, retrieved.Status)
		}
	}
}

func TestRegistryRepository_Integration_WithDataSources(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-datasrc-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	dataSources := []string{"customer_db", "product_api", "analytics_warehouse", "external_feed"}

	system := &AISystemRegistry{
		OrgID:               orgID,
		SystemID:            "sys-datasrc-" + uuid.New().String()[:8],
		SystemName:          "Data Sources Test",
		UseCase:             UseCaseOther,
		Status:              SystemStatusActive,
		RiskRatingImpact:    3,
		RiskRatingComplexity: 3,
		RiskRatingReliance:  3,
		OwnerTeam:           "Analytics Team",
		OwnerEmail:          "analytics@example.com",
		DataSources:         dataSources,
		CreatedBy:           "test-user",
	}

	if err := repo.Create(ctx, system); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := repo.GetByID(ctx, orgID, system.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if len(retrieved.DataSources) != 4 {
		t.Errorf("Expected 4 data sources, got %d", len(retrieved.DataSources))
	}
	if retrieved.DataSources[0] != "customer_db" {
		t.Errorf("Expected first data source 'customer_db', got %s", retrieved.DataSources[0])
	}
}

func TestRegistryRepository_Integration_WithMetadata(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-meta-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	metadata := map[string]interface{}{
		"environment":   "production",
		"region":        "asia-pacific",
		"cost_center":   "12345",
		"compliance":    []string{"MAS FEAT", "PDPA"},
		"annual_budget": 50000.00,
	}

	system := &AISystemRegistry{
		OrgID:               orgID,
		SystemID:            "sys-meta-" + uuid.New().String()[:8],
		SystemName:          "Metadata Test",
		UseCase:             UseCaseOther,
		Status:              SystemStatusActive,
		RiskRatingImpact:    4,
		RiskRatingComplexity: 4,
		RiskRatingReliance:  4,
		OwnerTeam:           "Compliance Team",
		OwnerEmail:          "compliance@example.com",
		Metadata:            metadata,
		CreatedBy:           "test-user",
	}

	if err := repo.Create(ctx, system); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := repo.GetByID(ctx, orgID, system.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Metadata == nil {
		t.Fatal("Expected Metadata to be set")
	}
	if retrieved.Metadata["environment"] != "production" {
		t.Errorf("Expected environment 'production', got %v", retrieved.Metadata["environment"])
	}
	if retrieved.Metadata["region"] != "asia-pacific" {
		t.Errorf("Expected region 'asia-pacific', got %v", retrieved.Metadata["region"])
	}
}

func TestRegistryRepository_Integration_DefaultLimits(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-reg-limits-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create 3 systems
	for i := 0; i < 3; i++ {
		system := &AISystemRegistry{
			OrgID:               orgID,
			SystemID:            "sys-limit-" + uuid.New().String()[:8],
			SystemName:          "Limit Test " + string(rune('A'+i)),
			UseCase:             UseCaseOther,
			Status:              SystemStatusActive,
			RiskRatingImpact:    3,
			RiskRatingComplexity: 3,
			RiskRatingReliance:  3,
			OwnerTeam:           "Test Team",
			OwnerEmail:          "test@example.com",
			CreatedBy:           "test-user",
		}
		if err := repo.Create(ctx, system); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// List with no limit specified (should use default)
	systems, err := repo.List(ctx, orgID, ListParams{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(systems) != 3 {
		t.Errorf("Expected all 3 systems with default limit, got %d", len(systems))
	}
}
