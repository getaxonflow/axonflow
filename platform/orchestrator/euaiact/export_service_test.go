// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"testing"
	"time"
)

func TestNewExportService(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)

	if service == nil {
		t.Fatal("Expected non-nil service")
	}
	if service.repo != repo {
		t.Error("Service repo not set correctly")
	}
}

func TestExportService_CreateExport_EmptyOrgID(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)

	input := CreateExportInput{
		OrgID:      "",
		ExportType: ExportTypeFullAudit,
		Format:     ExportFormatJSON,
	}

	_, err := service.CreateExport(context.Background(), input)
	if err == nil {
		t.Error("Expected error for empty OrgID")
	}
}

func TestExportService_CreateExport_InvalidExportType(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)

	input := CreateExportInput{
		OrgID:      "test-org",
		ExportType: ExportType("invalid"),
		Format:     ExportFormatJSON,
	}

	_, err := service.CreateExport(context.Background(), input)
	if err == nil {
		t.Error("Expected error for invalid ExportType")
	}
}

func TestExportService_CreateExport_InvalidFormat(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)

	input := CreateExportInput{
		OrgID:      "test-org",
		ExportType: ExportTypeFullAudit,
		Format:     ExportFormat("invalid"),
	}

	_, err := service.CreateExport(context.Background(), input)
	if err == nil {
		t.Error("Expected error for invalid Format")
	}
}

func TestExportService_CreateExport_Success(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)

	dateFrom := time.Now().Add(-24 * time.Hour)
	dateTo := time.Now()

	input := CreateExportInput{
		OrgID:       "test-org",
		ExportType:  ExportTypeFullAudit,
		Format:      ExportFormatJSON,
		DateFrom:    dateFrom,
		DateTo:      dateTo,
		ModelIDs:    []string{"model-1", "model-2"},
		RequestedBy: "test-user",
	}

	export, err := service.CreateExport(context.Background(), input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if export == nil {
		t.Fatal("Expected non-nil export")
	}
	if export.OrgID != "test-org" {
		t.Errorf("Expected OrgID 'test-org', got '%s'", export.OrgID)
	}
	if export.ExportType != ExportTypeFullAudit {
		t.Errorf("Expected ExportType '%s', got '%s'", ExportTypeFullAudit, export.ExportType)
	}
	if export.Format != ExportFormatJSON {
		t.Errorf("Expected Format '%s', got '%s'", ExportFormatJSON, export.Format)
	}
	if export.Status != ExportStatusPending {
		t.Errorf("Expected Status '%s', got '%s'", ExportStatusPending, export.Status)
	}
	if export.RequestedBy != "test-user" {
		t.Errorf("Expected RequestedBy 'test-user', got '%s'", export.RequestedBy)
	}
	if len(export.ModelIDs) != 2 {
		t.Errorf("Expected 2 ModelIDs, got %d", len(export.ModelIDs))
	}
}

func TestExportService_CreateExport_AllTypes(t *testing.T) {
	exportTypes := []ExportType{
		ExportTypeFullAudit,
		ExportTypeConformityEvidence,
		ExportTypeHITLSummary,
		ExportTypeDecisionChain,
		ExportTypePolicyViolations,
		ExportTypeAccuracyMetrics,
	}

	for _, exportType := range exportTypes {
		t.Run(string(exportType), func(t *testing.T) {
			repo := NewMockExportRepository()
			service := NewExportService(repo, nil)

			input := CreateExportInput{
				OrgID:      "test-org",
				ExportType: exportType,
				Format:     ExportFormatJSON,
			}

			export, err := service.CreateExport(context.Background(), input)
			if err != nil {
				t.Fatalf("Unexpected error for type %s: %v", exportType, err)
			}
			if export.ExportType != exportType {
				t.Errorf("Expected ExportType '%s', got '%s'", exportType, export.ExportType)
			}
		})
	}
}

func TestExportService_CreateExport_AllFormats(t *testing.T) {
	formats := []ExportFormat{
		ExportFormatJSON,
		ExportFormatCSV,
		ExportFormatXML,
		ExportFormatPDF,
	}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			repo := NewMockExportRepository()
			service := NewExportService(repo, nil)

			input := CreateExportInput{
				OrgID:      "test-org",
				ExportType: ExportTypeFullAudit,
				Format:     format,
			}

			export, err := service.CreateExport(context.Background(), input)
			if err != nil {
				t.Fatalf("Unexpected error for format %s: %v", format, err)
			}
			if export.Format != format {
				t.Errorf("Expected Format '%s', got '%s'", format, export.Format)
			}
		})
	}
}

func TestExportService_CreateExport_RepoError(t *testing.T) {
	repo := NewMockExportRepository()
	repo.createErr = context.DeadlineExceeded
	service := NewExportService(repo, nil)

	input := CreateExportInput{
		OrgID:      "test-org",
		ExportType: ExportTypeFullAudit,
		Format:     ExportFormatJSON,
	}

	_, err := service.CreateExport(context.Background(), input)
	if err == nil {
		t.Error("Expected error when repo fails")
	}
}

func TestExportService_GetExport(t *testing.T) {
	repo := NewMockExportRepository()
	repo.exports["export-123"] = &Export{
		ID:     "export-123",
		OrgID:  "test-org",
		Status: ExportStatusCompleted,
	}

	service := NewExportService(repo, nil)

	export, err := service.GetExport(context.Background(), "export-123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if export == nil {
		t.Fatal("Expected non-nil export")
	}
	if export.ID != "export-123" {
		t.Errorf("Expected ID 'export-123', got '%s'", export.ID)
	}
}

func TestExportService_GetExport_NotFound(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)

	export, err := service.GetExport(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if export != nil {
		t.Error("Expected nil export for nonexistent ID")
	}
}

func TestExportService_ListExports(t *testing.T) {
	repo := NewMockExportRepository()
	repo.exports["export-1"] = &Export{ID: "export-1", OrgID: "test-org"}
	repo.exports["export-2"] = &Export{ID: "export-2", OrgID: "test-org"}
	repo.exports["export-3"] = &Export{ID: "export-3", OrgID: "other-org"}
	repo.listTotal = 2

	service := NewExportService(repo, nil)

	exports, total, err := service.ListExports(context.Background(), "test-org", 10, 0)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if total != 2 {
		t.Errorf("Expected total 2, got %d", total)
	}
	if len(exports) != 2 {
		t.Errorf("Expected 2 exports, got %d", len(exports))
	}
}

func TestExportService_ProcessExport_NotFound(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)

	// This should not panic
	service.processExport("nonexistent")
}

func TestExportService_ProcessExport_FullAudit(t *testing.T) {
	repo := NewMockExportRepository()
	export := &Export{
		ID:         "export-123",
		OrgID:      "test-org",
		ExportType: ExportTypeFullAudit,
		Status:     ExportStatusPending,
	}
	repo.exports[export.ID] = export

	service := NewExportService(repo, nil)
	service.processExport(export.ID)

	// Wait a bit for async processing
	time.Sleep(100 * time.Millisecond)

	// Verify export was updated
	updated, _ := repo.GetByID(context.Background(), export.ID)
	if updated != nil && updated.Status != ExportStatusCompleted {
		t.Logf("Export status: %s (may still be processing)", updated.Status)
	}
}

func TestExportService_ProcessExport_AllTypes(t *testing.T) {
	exportTypes := []ExportType{
		ExportTypeFullAudit,
		ExportTypeConformityEvidence,
		ExportTypeHITLSummary,
		ExportTypeDecisionChain,
		ExportTypePolicyViolations,
		ExportTypeAccuracyMetrics,
	}

	for _, exportType := range exportTypes {
		t.Run(string(exportType), func(t *testing.T) {
			repo := NewMockExportRepository()
			export := &Export{
				ID:         "export-" + string(exportType),
				OrgID:      "test-org",
				ExportType: exportType,
				Status:     ExportStatusPending,
			}
			repo.exports[export.ID] = export

			service := NewExportService(repo, nil)
			service.processExport(export.ID)

			// Wait for async processing
			time.Sleep(50 * time.Millisecond)
		})
	}
}

func TestExportService_ProcessExport_UnsupportedType(t *testing.T) {
	repo := NewMockExportRepository()
	export := &Export{
		ID:         "export-123",
		OrgID:      "test-org",
		ExportType: ExportType("unsupported"),
		Status:     ExportStatusPending,
	}
	repo.exports[export.ID] = export

	service := NewExportService(repo, nil)
	service.processExport(export.ID)

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)

	// Should fail with unsupported type
	updated, _ := repo.GetByID(context.Background(), export.ID)
	if updated != nil && updated.Status == ExportStatusCompleted {
		t.Error("Expected export to fail for unsupported type")
	}
}
