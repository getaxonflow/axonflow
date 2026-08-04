// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Integration tests for ExportRepository
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
		// Create test organization
		// Note: organizations table schema doesn't have display_name column
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

func cleanupTestExports(t *testing.T, db *sql.DB, orgID string) {
	_, err := db.Exec("DELETE FROM euaiact_exports WHERE org_id = $1", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup exports: %v", err)
	}
}

func TestExportRepository_Integration_NewPostgresExportRepository(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected repository to have the provided database connection")
	}
}

func TestExportRepository_Integration_Create(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-create-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	export := &Export{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ExportType:  ExportTypeFullAudit,
		Format:      ExportFormatJSON,
		Status:      ExportStatusPending,
		Progress:    0,
		RequestedBy: "test-user",
		CreatedAt:   time.Now().UTC(),
		Filters:     map[string]interface{}{"model": "test-model"},
		ModelIDs:    []string{"model-1", "model-2"},
	}

	err := repo.Create(ctx, export)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify by retrieving
	retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected export to be found")
	}
	if retrieved.ID != export.ID {
		t.Errorf("Expected ID %s, got %s", export.ID, retrieved.ID)
	}
	if retrieved.OrgID != orgID {
		t.Errorf("Expected OrgID %s, got %s", orgID, retrieved.OrgID)
	}
	if retrieved.ExportType != ExportTypeFullAudit {
		t.Errorf("Expected ExportType %s, got %s", ExportTypeFullAudit, retrieved.ExportType)
	}
	if retrieved.Format != ExportFormatJSON {
		t.Errorf("Expected Format %s, got %s", ExportFormatJSON, retrieved.Format)
	}
	if retrieved.Status != ExportStatusPending {
		t.Errorf("Expected Status %s, got %s", ExportStatusPending, retrieved.Status)
	}
	if len(retrieved.ModelIDs) != 2 {
		t.Errorf("Expected 2 model IDs, got %d", len(retrieved.ModelIDs))
	}
}

func TestExportRepository_Integration_GetByID_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	// #3241: a miss now returns ErrExportNotFound rather than (nil, nil) - the
	// handler needs a value it can map to 404, and "no such id" must be
	// indistinguishable from "belongs to another organization".
	retrieved, err := repo.GetByID(ctx, "test-org-nonexistent-lookup", "non-existent-export-id")
	if !errors.Is(err, ErrExportNotFound) {
		t.Fatalf("GetByID() error = %v, want ErrExportNotFound", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for non-existent ID")
	}
}

func TestExportRepository_Integration_List(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-list-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	// Create multiple exports
	exportTypes := []ExportType{ExportTypeFullAudit, ExportTypeHITLSummary, ExportTypeAccuracyMetrics}
	for i, et := range exportTypes {
		export := &Export{
			ID:          uuid.New().String(),
			OrgID:       orgID,
			ExportType:  et,
			Format:      ExportFormatJSON,
			Status:      ExportStatusPending,
			Progress:    i * 30,
			RequestedBy: "test-user",
			CreatedAt:   time.Now().UTC().Add(time.Duration(i) * time.Minute),
		}
		if err := repo.Create(ctx, export); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// List all exports
	exports, total, err := repo.List(ctx, orgID, 10, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 3 {
		t.Errorf("Expected total 3, got %d", total)
	}
	if len(exports) != 3 {
		t.Errorf("Expected 3 exports, got %d", len(exports))
	}

	// Verify ordering (most recent first)
	if exports[0].ExportType != ExportTypeAccuracyMetrics {
		t.Errorf("Expected most recent export first, got %s", exports[0].ExportType)
	}
}

func TestExportRepository_Integration_List_Pagination(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-page-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	// Create 5 exports
	for i := 0; i < 5; i++ {
		export := &Export{
			ID:          uuid.New().String(),
			OrgID:       orgID,
			ExportType:  ExportTypeFullAudit,
			Format:      ExportFormatJSON,
			Status:      ExportStatusPending,
			Progress:    0,
			RequestedBy: "test-user",
			CreatedAt:   time.Now().UTC().Add(time.Duration(i) * time.Second),
		}
		if err := repo.Create(ctx, export); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Get first page (2 items)
	exports, total, err := repo.List(ctx, orgID, 2, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 5 {
		t.Errorf("Expected total 5, got %d", total)
	}
	if len(exports) != 2 {
		t.Errorf("Expected 2 exports on page 1, got %d", len(exports))
	}

	// Get second page
	exports2, _, err := repo.List(ctx, orgID, 2, 2)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(exports2) != 2 {
		t.Errorf("Expected 2 exports on page 2, got %d", len(exports2))
	}

	// Get third page (remaining 1)
	exports3, _, err := repo.List(ctx, orgID, 2, 4)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(exports3) != 1 {
		t.Errorf("Expected 1 export on page 3, got %d", len(exports3))
	}
}

func TestExportRepository_Integration_Update(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-update-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	// Create an export
	export := &Export{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ExportType:  ExportTypeFullAudit,
		Format:      ExportFormatJSON,
		Status:      ExportStatusPending,
		Progress:    0,
		RequestedBy: "test-user",
		CreatedAt:   time.Now().UTC(),
	}
	if err := repo.Create(ctx, export); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update the export
	startTime := time.Now().UTC()
	export.Status = ExportStatusProcessing
	export.Progress = 50
	export.StartedAt = &startTime

	err := repo.Update(ctx, export)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify update
	retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != ExportStatusProcessing {
		t.Errorf("Expected Status %s, got %s", ExportStatusProcessing, retrieved.Status)
	}
	if retrieved.Progress != 50 {
		t.Errorf("Expected Progress 50, got %d", retrieved.Progress)
	}
	if retrieved.StartedAt == nil {
		t.Error("Expected StartedAt to be set")
	}
}

func TestExportRepository_Integration_Update_Complete(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-complete-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	// Create an export
	export := &Export{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ExportType:  ExportTypeHITLSummary,
		Format:      ExportFormatCSV,
		Status:      ExportStatusPending,
		Progress:    0,
		RequestedBy: "test-user",
		CreatedAt:   time.Now().UTC(),
	}
	if err := repo.Create(ctx, export); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Complete the export
	completedTime := time.Now().UTC()
	export.Status = ExportStatusCompleted
	export.Progress = 100
	export.FilePath = "/exports/test-export.csv"
	export.FileSize = 12345
	export.RecordCount = 100
	export.CompletedAt = &completedTime

	err := repo.Update(ctx, export)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != ExportStatusCompleted {
		t.Errorf("Expected Status %s, got %s", ExportStatusCompleted, retrieved.Status)
	}
	if retrieved.Progress != 100 {
		t.Errorf("Expected Progress 100, got %d", retrieved.Progress)
	}
	if retrieved.FilePath != "/exports/test-export.csv" {
		t.Errorf("Expected FilePath %s, got %s", "/exports/test-export.csv", retrieved.FilePath)
	}
	if retrieved.FileSize != 12345 {
		t.Errorf("Expected FileSize 12345, got %d", retrieved.FileSize)
	}
	if retrieved.RecordCount != 100 {
		t.Errorf("Expected RecordCount 100, got %d", retrieved.RecordCount)
	}
}

func TestExportRepository_Integration_Update_Failed(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-failed-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	// Create an export
	export := &Export{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ExportType:  ExportTypeDecisionChain,
		Format:      ExportFormatPDF,
		Status:      ExportStatusProcessing,
		Progress:    25,
		RequestedBy: "test-user",
		CreatedAt:   time.Now().UTC(),
	}
	if err := repo.Create(ctx, export); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Fail the export
	completedTime := time.Now().UTC()
	export.Status = ExportStatusFailed
	export.Error = "Database connection timeout"
	export.CompletedAt = &completedTime

	err := repo.Update(ctx, export)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != ExportStatusFailed {
		t.Errorf("Expected Status %s, got %s", ExportStatusFailed, retrieved.Status)
	}
	if retrieved.Error != "Database connection timeout" {
		t.Errorf("Expected Error message, got %s", retrieved.Error)
	}
}

func TestExportRepository_Integration_Delete(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-delete-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	// Create an export
	export := &Export{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ExportType:  ExportTypeFullAudit,
		Format:      ExportFormatJSON,
		Status:      ExportStatusCompleted,
		Progress:    100,
		RequestedBy: "test-user",
		CreatedAt:   time.Now().UTC(),
	}
	if err := repo.Create(ctx, export); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete the export
	err := repo.Delete(ctx, export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deletion
	retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected export to be deleted")
	}
}

func TestExportRepository_Integration_AllExportTypes(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-types-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	// Test all export types
	exportTypes := []ExportType{
		ExportTypeFullAudit,
		ExportTypeConformityEvidence,
		ExportTypeHITLSummary,
		ExportTypeDecisionChain,
		ExportTypePolicyViolations,
		ExportTypeAccuracyMetrics,
	}

	for _, et := range exportTypes {
		export := &Export{
			ID:          uuid.New().String(),
			OrgID:       orgID,
			ExportType:  et,
			Format:      ExportFormatJSON,
			Status:      ExportStatusPending,
			Progress:    0,
			RequestedBy: "test-user",
			CreatedAt:   time.Now().UTC(),
		}
		if err := repo.Create(ctx, export); err != nil {
			t.Fatalf("Create() error for type %s: %v", et, err)
		}

		retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
		if err != nil {
			t.Fatalf("GetByID() error for type %s: %v", et, err)
		}
		if retrieved.ExportType != et {
			t.Errorf("Expected ExportType %s, got %s", et, retrieved.ExportType)
		}
	}
}

func TestExportRepository_Integration_AllExportFormats(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-formats-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	// Test all export formats
	formats := []ExportFormat{
		ExportFormatJSON,
		ExportFormatCSV,
		ExportFormatXML,
		ExportFormatPDF,
	}

	for _, f := range formats {
		export := &Export{
			ID:          uuid.New().String(),
			OrgID:       orgID,
			ExportType:  ExportTypeFullAudit,
			Format:      f,
			Status:      ExportStatusPending,
			Progress:    0,
			RequestedBy: "test-user",
			CreatedAt:   time.Now().UTC(),
		}
		if err := repo.Create(ctx, export); err != nil {
			t.Fatalf("Create() error for format %s: %v", f, err)
		}

		retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
		if err != nil {
			t.Fatalf("GetByID() error for format %s: %v", f, err)
		}
		if retrieved.Format != f {
			t.Errorf("Expected Format %s, got %s", f, retrieved.Format)
		}
	}
}

func TestExportRepository_Integration_WithDateRange(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-dates-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	dateFrom := time.Now().UTC().AddDate(0, 0, -30)
	dateTo := time.Now().UTC()

	export := &Export{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ExportType:  ExportTypeFullAudit,
		Format:      ExportFormatJSON,
		Status:      ExportStatusPending,
		Progress:    0,
		DateFrom:    dateFrom,
		DateTo:      dateTo,
		RequestedBy: "test-user",
		CreatedAt:   time.Now().UTC(),
	}
	if err := repo.Create(ctx, export); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.DateFrom.IsZero() {
		t.Error("Expected DateFrom to be set")
	}
	if retrieved.DateTo.IsZero() {
		t.Error("Expected DateTo to be set")
	}
}

func TestExportRepository_Integration_WithFilters(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-export-filters-"+time.Now().Format("20060102150405"))
	defer cleanupTestExports(t, db, orgID)

	ctx := context.Background()

	filters := map[string]interface{}{
		"risk_level":  "high",
		"department":  "engineering",
		"model_types": []string{"llm", "classifier"},
	}

	export := &Export{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ExportType:  ExportTypeFullAudit,
		Format:      ExportFormatJSON,
		Status:      ExportStatusPending,
		Progress:    0,
		Filters:     filters,
		RequestedBy: "test-user",
		CreatedAt:   time.Now().UTC(),
	}
	if err := repo.Create(ctx, export); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := repo.GetByID(ctx, export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Filters == nil {
		t.Error("Expected Filters to be set")
	}
	if retrieved.Filters["risk_level"] != "high" {
		t.Errorf("Expected risk_level filter to be 'high', got %v", retrieved.Filters["risk_level"])
	}
}
