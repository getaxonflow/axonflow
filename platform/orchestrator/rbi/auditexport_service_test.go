// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// MockAuditExportRepository implements AuditExportRepository for testing.
type MockAuditExportRepository struct {
	exports map[string]*AuditExport
	counter int
}

func NewMockAuditExportRepository() *MockAuditExportRepository {
	return &MockAuditExportRepository{
		exports: make(map[string]*AuditExport),
		counter: 0,
	}
}

func (m *MockAuditExportRepository) Create(ctx context.Context, export *AuditExport) error {
	if export.ID == "" {
		m.counter++
		export.ID = fmt.Sprintf("export-%d", m.counter)
	}
	export.CreatedAt = time.Now().UTC()
	export.UpdatedAt = export.CreatedAt
	m.exports[export.ID] = export
	return nil
}

func (m *MockAuditExportRepository) Get(ctx context.Context, orgID, id string) (*AuditExport, error) {
	export, ok := m.exports[id]
	if !ok || export.OrgID != orgID {
		return nil, ErrAuditExportNotFound
	}
	return export, nil
}

func (m *MockAuditExportRepository) List(ctx context.Context, orgID string, params *ListAuditExportsParams) ([]*AuditExport, int, error) {
	var result []*AuditExport
	for _, export := range m.exports {
		if export.OrgID != orgID {
			continue
		}
		if params != nil {
			if params.ExportType != "" && string(export.ExportType) != params.ExportType {
				continue
			}
			if params.Status != "" && string(export.Status) != params.Status {
				continue
			}
		}
		result = append(result, export)
	}
	return result, len(result), nil
}

func (m *MockAuditExportRepository) Update(ctx context.Context, export *AuditExport) error {
	if _, ok := m.exports[export.ID]; !ok {
		return ErrAuditExportNotFound
	}
	export.UpdatedAt = time.Now().UTC()
	m.exports[export.ID] = export
	return nil
}

func (m *MockAuditExportRepository) Delete(ctx context.Context, orgID, id string) error {
	export, ok := m.exports[id]
	if !ok || export.OrgID != orgID {
		return ErrAuditExportNotFound
	}
	delete(m.exports, id)
	return nil
}

func (m *MockAuditExportRepository) GetPending(ctx context.Context) ([]*AuditExport, error) {
	var result []*AuditExport
	for _, export := range m.exports {
		if export.Status == AuditExportStatusPending {
			result = append(result, export)
		}
	}
	return result, nil
}

func (m *MockAuditExportRepository) GetExpired(ctx context.Context) ([]*AuditExport, error) {
	var result []*AuditExport
	now := time.Now()
	for _, export := range m.exports {
		if export.ExpiresAt != nil && export.ExpiresAt.Before(now) && export.Status == AuditExportStatusCompleted {
			result = append(result, export)
		}
	}
	return result, nil
}

// MockIncidentRepository implements AIIncidentRepository for testing in audit export.
type MockIncidentRepository struct {
	incidents map[string]*AIIncident
}

func NewMockIncidentRepository() *MockIncidentRepository {
	return &MockIncidentRepository{
		incidents: make(map[string]*AIIncident),
	}
}

func (m *MockIncidentRepository) Create(ctx context.Context, incident *AIIncident) error {
	if incident.ID == "" {
		incident.ID = "inc-" + time.Now().Format("20060102150405")
	}
	incident.CreatedAt = time.Now().UTC()
	incident.UpdatedAt = incident.CreatedAt
	m.incidents[incident.ID] = incident
	return nil
}

func (m *MockIncidentRepository) Get(ctx context.Context, orgID, id string) (*AIIncident, error) {
	inc, ok := m.incidents[id]
	if !ok || inc.OrgID != orgID {
		return nil, ErrIncidentNotFound
	}
	return inc, nil
}

func (m *MockIncidentRepository) GetByIncidentID(ctx context.Context, orgID, incidentID string) (*AIIncident, error) {
	for _, inc := range m.incidents {
		if inc.OrgID == orgID && inc.IncidentID == incidentID {
			return inc, nil
		}
	}
	return nil, ErrIncidentNotFound
}

func (m *MockIncidentRepository) List(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error) {
	var result []*AIIncident
	for _, inc := range m.incidents {
		if inc.OrgID != orgID {
			continue
		}
		if params != nil && params.SystemID != "" && inc.SystemID != params.SystemID {
			continue
		}
		result = append(result, inc)
	}
	return result, len(result), nil
}

func (m *MockIncidentRepository) ListBySystem(ctx context.Context, orgID, systemID string) ([]*AIIncident, error) {
	var result []*AIIncident
	for _, inc := range m.incidents {
		if inc.OrgID == orgID && inc.SystemID == systemID {
			result = append(result, inc)
		}
	}
	return result, nil
}

func (m *MockIncidentRepository) Update(ctx context.Context, incident *AIIncident) error {
	if _, ok := m.incidents[incident.ID]; !ok {
		return ErrIncidentNotFound
	}
	incident.UpdatedAt = time.Now().UTC()
	m.incidents[incident.ID] = incident
	return nil
}

func (m *MockIncidentRepository) Delete(ctx context.Context, orgID, id string) error {
	inc, ok := m.incidents[id]
	if !ok || inc.OrgID != orgID {
		return ErrIncidentNotFound
	}
	delete(m.incidents, id)
	return nil
}

func (m *MockIncidentRepository) GetOpenIncidents(ctx context.Context, orgID string) ([]*AIIncident, error) {
	var result []*AIIncident
	for _, inc := range m.incidents {
		if inc.OrgID == orgID && inc.Status != IncidentStatusResolved && inc.Status != IncidentStatusClosed {
			result = append(result, inc)
		}
	}
	return result, nil
}

func (m *MockIncidentRepository) GetPendingNotifications(ctx context.Context, orgID string, notificationType string) ([]*AIIncident, error) {
	var result []*AIIncident
	for _, inc := range m.incidents {
		if inc.OrgID == orgID {
			if notificationType == "board" && !inc.BoardNotified {
				result = append(result, inc)
			}
			if notificationType == "rbi" && !inc.RBINotified {
				result = append(result, inc)
			}
		}
	}
	return result, nil
}

func TestAuditExportService_CreateExport(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)

	ctx := context.Background()

	tests := []struct {
		name    string
		req     *CreateExportRequest
		wantErr bool
	}{
		{
			name: "valid full export",
			req: &CreateExportRequest{
				OrgID:            "org-1",
				ExportType:       AuditExportTypeFull,
				Format:           AuditExportFormatJSON,
				RequestedBy:      "user-1",
				RequestedByEmail: "user@example.com",
				Purpose:          "RBI Compliance Audit",
			},
			wantErr: false,
		},
		{
			name: "valid systems export with date range",
			req: &CreateExportRequest{
				OrgID:      "org-1",
				ExportType: AuditExportTypeSystems,
				Format:     AuditExportFormatCSV,
				StartDate:  timePtr(time.Now().AddDate(0, -1, 0)),
				EndDate:    timePtr(time.Now()),
			},
			wantErr: false,
		},
		{
			name: "valid incidents export with system filter",
			req: &CreateExportRequest{
				OrgID:      "org-1",
				ExportType: AuditExportTypeIncidents,
				Format:     AuditExportFormatPDF,
				SystemIDs:  []string{"sys-1", "sys-2"},
			},
			wantErr: false,
		},
		{
			name: "missing org_id",
			req: &CreateExportRequest{
				ExportType: AuditExportTypeFull,
				Format:     AuditExportFormatJSON,
			},
			wantErr: true,
		},
		{
			name: "invalid export type",
			req: &CreateExportRequest{
				OrgID:      "org-1",
				ExportType: AuditExportType("invalid"),
				Format:     AuditExportFormatJSON,
			},
			wantErr: true,
		},
		{
			name: "invalid format",
			req: &CreateExportRequest{
				OrgID:      "org-1",
				ExportType: AuditExportTypeFull,
				Format:     AuditExportFormat("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			export, err := service.CreateExport(ctx, tt.req)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if export.ID == "" {
				t.Error("expected export ID to be set")
			}
			if export.Status != AuditExportStatusPending {
				t.Errorf("expected status pending, got %s", export.Status)
			}
			if export.OrgID != tt.req.OrgID {
				t.Errorf("expected org_id %s, got %s", tt.req.OrgID, export.OrgID)
			}
		})
	}
}

func TestAuditExportService_GetExport(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)

	ctx := context.Background()

	// Create an export
	export, err := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})
	if err != nil {
		t.Fatalf("failed to create export: %v", err)
	}

	// Test get
	retrieved, err := service.GetExport(ctx, "org-1", export.ID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	if retrieved.ID != export.ID {
		t.Errorf("expected ID %s, got %s", export.ID, retrieved.ID)
	}

	// Test get with wrong org
	_, err = service.GetExport(ctx, "org-2", export.ID)
	if err != ErrAuditExportNotFound {
		t.Errorf("expected ErrAuditExportNotFound, got %v", err)
	}

	// Test get non-existent
	_, err = service.GetExport(ctx, "org-1", "non-existent")
	if err != ErrAuditExportNotFound {
		t.Errorf("expected ErrAuditExportNotFound, got %v", err)
	}
}

func TestAuditExportService_ListExports(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)

	ctx := context.Background()

	// Create multiple exports
	service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})
	service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeSystems,
		Format:     AuditExportFormatCSV,
	})
	service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-2",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})

	// List for org-1
	exports, total, err := service.ListExports(ctx, "org-1", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	if total != 2 {
		t.Errorf("expected 2 exports, got %d", total)
	}
	if len(exports) != 2 {
		t.Errorf("expected 2 exports, got %d", len(exports))
	}

	// List with filter
	exports, total, err = service.ListExports(ctx, "org-1", &ListAuditExportsParams{
		ExportType: "systems",
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	if total != 1 {
		t.Errorf("expected 1 export, got %d", total)
	}
}

func TestAuditExportService_DeleteExport(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)

	ctx := context.Background()

	// Create an export
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})

	// Delete
	err := service.DeleteExport(ctx, "org-1", export.ID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify deleted
	_, err = service.GetExport(ctx, "org-1", export.ID)
	if err != ErrAuditExportNotFound {
		t.Errorf("expected ErrAuditExportNotFound, got %v", err)
	}

	// Delete non-existent
	err = service.DeleteExport(ctx, "org-1", "non-existent")
	if err != ErrAuditExportNotFound {
		t.Errorf("expected ErrAuditExportNotFound, got %v", err)
	}
}

func TestAuditExportService_ProcessExport(t *testing.T) {
	// Create temp directory for exports
	tmpDir := t.TempDir()

	repo := NewMockAuditExportRepository()
	systemRepo := NewMockAISystemRepository()
	validationRepo := NewMockModelValidationRepository()
	incidentRepo := NewMockIncidentRepository()
	killSwitchRepo := NewMockKillSwitchRepository()
	reportRepo := NewMockBoardReportRepository()

	service := NewAuditExportService(repo, systemRepo, validationRepo, incidentRepo, killSwitchRepo, reportRepo, tmpDir, nil)

	ctx := context.Background()

	// Add some test data
	systemRepo.Create(ctx, &AISystem{
		OrgID:            "org-1",
		SystemName:       "Test System",
		RiskCategory:     RiskCategoryHigh,
		DeploymentStatus: DeploymentStatusProduction,
	})

	// Create an export
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:            "org-1",
		ExportType:       AuditExportTypeFull,
		Format:           AuditExportFormatJSON,
		RequestedBy:      "user-1",
		RequestedByEmail: "user@example.com",
		Purpose:          "Test Export",
	})

	// Process the export
	err := service.ProcessExport(ctx, export)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify export was updated
	processed, _ := service.GetExport(ctx, "org-1", export.ID)
	if processed.Status != AuditExportStatusCompleted {
		t.Errorf("expected status completed, got %s", processed.Status)
	}
	if processed.FilePath == "" {
		t.Error("expected file path to be set")
	}
	if processed.FileChecksum == "" {
		t.Error("expected file checksum to be set")
	}
	if processed.RecordCount != 1 {
		t.Errorf("expected 1 record, got %d", processed.RecordCount)
	}
	if processed.Summary == nil {
		t.Error("expected summary to be set")
	}
	if processed.Summary.TotalSystems != 1 {
		t.Errorf("expected 1 system in summary, got %d", processed.Summary.TotalSystems)
	}

	// Verify file exists
	if _, err := os.Stat(processed.FilePath); os.IsNotExist(err) {
		t.Error("export file does not exist")
	}
}

func TestAuditExportService_ProcessExport_CSV(t *testing.T) {
	tmpDir := t.TempDir()

	repo := NewMockAuditExportRepository()
	systemRepo := NewMockAISystemRepository()
	service := NewAuditExportService(repo, systemRepo, nil, nil, nil, nil, tmpDir, nil)

	ctx := context.Background()

	// Add test data
	systemRepo.Create(ctx, &AISystem{
		OrgID:            "org-1",
		SystemName:       "System 1",
		RiskCategory:     RiskCategoryHigh,
		DeploymentStatus: DeploymentStatusProduction,
	})
	systemRepo.Create(ctx, &AISystem{
		OrgID:            "org-1",
		SystemName:       "System 2",
		RiskCategory:     RiskCategoryMedium,
		DeploymentStatus: DeploymentStatusProduction,
	})

	// Create CSV export
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeSystems,
		Format:     AuditExportFormatCSV,
	})

	err := service.ProcessExport(ctx, export)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	processed, _ := service.GetExport(ctx, "org-1", export.ID)
	if processed.Status != AuditExportStatusCompleted {
		t.Errorf("expected status completed, got %s", processed.Status)
	}

	// Read and verify CSV content
	content, err := os.ReadFile(processed.FilePath)
	if err != nil {
		t.Errorf("failed to read CSV file: %v", err)
		return
	}
	if len(content) == 0 {
		t.Error("CSV file is empty")
	}
}

func TestAuditExportService_GetExportFile(t *testing.T) {
	tmpDir := t.TempDir()

	repo := NewMockAuditExportRepository()
	systemRepo := NewMockAISystemRepository()
	service := NewAuditExportService(repo, systemRepo, nil, nil, nil, nil, tmpDir, nil)

	ctx := context.Background()

	// Add test data
	systemRepo.Create(ctx, &AISystem{
		OrgID:            "org-1",
		SystemName:       "Test System",
		RiskCategory:     RiskCategoryHigh,
		DeploymentStatus: DeploymentStatusProduction,
	})

	// Create and process export
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeSystems,
		Format:     AuditExportFormatJSON,
	})
	service.ProcessExport(ctx, export)

	// Get export file
	content, filename, err := service.GetExportFile(ctx, "org-1", export.ID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	if len(content) == 0 {
		t.Error("expected content to be non-empty")
	}
	if filename == "" {
		t.Error("expected filename to be non-empty")
	}
}

func TestAuditExportService_GetExportFile_NotCompleted(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)

	ctx := context.Background()

	// Create export but don't process
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})

	// Try to get file
	_, _, err := service.GetExportFile(ctx, "org-1", export.ID)
	if err == nil {
		t.Error("expected error for non-completed export")
	}
}

func TestAuditExportService_ProcessPendingExports(t *testing.T) {
	tmpDir := t.TempDir()

	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, tmpDir, nil)

	ctx := context.Background()

	// Create multiple pending exports
	service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})
	service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-2",
		ExportType: AuditExportTypeSystems,
		Format:     AuditExportFormatCSV,
	})

	// Process all pending
	err := service.ProcessPendingExports(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify all are completed
	exports1, _, _ := service.ListExports(ctx, "org-1", nil)
	for _, e := range exports1 {
		if e.Status != AuditExportStatusCompleted {
			t.Errorf("expected export %s to be completed, got %s", e.ID, e.Status)
		}
	}

	exports2, _, _ := service.ListExports(ctx, "org-2", nil)
	for _, e := range exports2 {
		if e.Status != AuditExportStatusCompleted {
			t.Errorf("expected export %s to be completed, got %s", e.ID, e.Status)
		}
	}
}

func TestAuditExportService_CleanupExpiredExports(t *testing.T) {
	tmpDir := t.TempDir()

	repo := NewMockAuditExportRepository()
	systemRepo := NewMockAISystemRepository()
	service := NewAuditExportService(repo, systemRepo, nil, nil, nil, nil, tmpDir, nil)

	ctx := context.Background()

	// Create and process an export
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})
	service.ProcessExport(ctx, export)

	// Manually set expiration to past
	processed, _ := service.GetExport(ctx, "org-1", export.ID)
	pastTime := time.Now().Add(-24 * time.Hour)
	processed.ExpiresAt = &pastTime
	repo.Update(ctx, processed)

	// Cleanup
	err := service.CleanupExpiredExports(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify status is expired
	updated, _ := service.GetExport(ctx, "org-1", export.ID)
	if updated.Status != AuditExportStatusExpired {
		t.Errorf("expected status expired, got %s", updated.Status)
	}
}

func TestAuditExportService_CollectData_WithFilters(t *testing.T) {
	tmpDir := t.TempDir()

	repo := NewMockAuditExportRepository()
	systemRepo := NewMockAISystemRepository()
	incidentRepo := NewMockIncidentRepository()

	service := NewAuditExportService(repo, systemRepo, nil, incidentRepo, nil, nil, tmpDir, nil)

	ctx := context.Background()

	// Add test data
	sys1 := &AISystem{
		OrgID:            "org-1",
		SystemName:       "High Risk System",
		RiskCategory:     RiskCategoryHigh,
		DeploymentStatus: DeploymentStatusProduction,
	}
	systemRepo.Create(ctx, sys1)

	sys2 := &AISystem{
		OrgID:            "org-1",
		SystemName:       "Low Risk System",
		RiskCategory:     RiskCategoryLow,
		DeploymentStatus: DeploymentStatusDeprecated,
	}
	systemRepo.Create(ctx, sys2)

	// Create export with filters (exclude archived, specific risk category)
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:           "org-1",
		ExportType:      AuditExportTypeSystems,
		Format:          AuditExportFormatJSON,
		IncludeArchived: false,
		RiskCategories:  []string{"high"},
	})

	err := service.ProcessExport(ctx, export)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	processed, _ := service.GetExport(ctx, "org-1", export.ID)
	// Should only include 1 system (high risk, not archived)
	if processed.Summary.TotalSystems != 1 {
		t.Errorf("expected 1 system (filtered), got %d", processed.Summary.TotalSystems)
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
