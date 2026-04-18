// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"fmt"
	"time"

	"axonflow/platform/orchestrator/cloudstorage"

	"github.com/google/uuid"
)

// ExportService provides business logic for EU AI Act exports.
type ExportService struct {
	repo           ExportRepository
	storageBackend cloudstorage.StorageBackend
}

// NewExportService creates a new export service.
func NewExportService(repo ExportRepository, storageBackend cloudstorage.StorageBackend) *ExportService {
	return &ExportService{repo: repo, storageBackend: storageBackend}
}

// GetExportDownloadURL generates a presigned download URL for a completed export.
// If the export has a StorageKey and a storage backend is configured, it returns
// a time-limited presigned URL. Otherwise it returns an empty string.
func (s *ExportService) GetExportDownloadURL(ctx context.Context, exportID string) (string, error) {
	export, err := s.repo.GetByID(ctx, exportID)
	if err != nil {
		return "", fmt.Errorf("get export: %w", err)
	}
	if export == nil {
		return "", fmt.Errorf("export not found: %s", exportID)
	}
	if export.StorageKey == "" || s.storageBackend == nil {
		return "", nil
	}

	url, err := s.storageBackend.GeneratePresignedURL(ctx, export.StorageKey, 1*time.Hour)
	if err != nil {
		return "", fmt.Errorf("generate presigned URL: %w", err)
	}
	return url, nil
}

// CreateExportInput contains input for creating an export.
type CreateExportInput struct {
	OrgID       string
	ExportType  ExportType
	Format      ExportFormat
	DateFrom    time.Time
	DateTo      time.Time
	ModelIDs    []string
	Filters     map[string]interface{}
	RequestedBy string
}

// CreateExport creates a new export job.
func (s *ExportService) CreateExport(ctx context.Context, input CreateExportInput) (*Export, error) {
	if input.OrgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	if !input.ExportType.Valid() {
		return nil, fmt.Errorf("invalid export_type: %s", input.ExportType)
	}
	if !input.Format.Valid() {
		return nil, fmt.Errorf("invalid format: %s", input.Format)
	}

	export := &Export{
		ID:          "export-" + uuid.New().String()[:8],
		OrgID:       input.OrgID,
		ExportType:  input.ExportType,
		Format:      input.Format,
		Status:      ExportStatusPending,
		Progress:    0,
		DateFrom:    input.DateFrom,
		DateTo:      input.DateTo,
		ModelIDs:    input.ModelIDs,
		Filters:     input.Filters,
		RequestedBy: input.RequestedBy,
		CreatedAt:   time.Now().UTC(),
	}

	if err := s.repo.Create(ctx, export); err != nil {
		return nil, fmt.Errorf("create export: %w", err)
	}

	// Return a snapshot copy so the async goroutine doesn't mutate the caller's view.
	// The copy must be made BEFORE launching the goroutine to avoid a data race.
	result := *export

	// Start async export processing
	go s.processExport(export.ID)

	return &result, nil
}

// GetExport retrieves an export by ID.
func (s *ExportService) GetExport(ctx context.Context, id string) (*Export, error) {
	return s.repo.GetByID(ctx, id)
}

// ListExports retrieves exports for an organization.
func (s *ExportService) ListExports(ctx context.Context, orgID string, limit, offset int) ([]*Export, int64, error) {
	return s.repo.List(ctx, orgID, limit, offset)
}

// processExport processes an export job asynchronously.
func (s *ExportService) processExport(exportID string) {
	ctx := context.Background()

	export, err := s.repo.GetByID(ctx, exportID)
	if err != nil || export == nil {
		return
	}

	// Update status to processing
	now := time.Now().UTC()
	export.Status = ExportStatusProcessing
	export.StartedAt = &now
	s.repo.Update(ctx, export)

	// Process based on export type
	var processErr error
	switch export.ExportType {
	case ExportTypeFullAudit:
		processErr = s.processFullAuditExport(ctx, export)
	case ExportTypeConformityEvidence:
		processErr = s.processConformityExport(ctx, export)
	case ExportTypeHITLSummary:
		processErr = s.processHITLExport(ctx, export)
	case ExportTypeDecisionChain:
		processErr = s.processDecisionChainExport(ctx, export)
	case ExportTypePolicyViolations:
		processErr = s.processPolicyViolationsExport(ctx, export)
	case ExportTypeAccuracyMetrics:
		processErr = s.processAccuracyExport(ctx, export)
	default:
		processErr = fmt.Errorf("unsupported export type: %s", export.ExportType)
	}

	// Update final status
	completed := time.Now().UTC()
	export.CompletedAt = &completed
	if processErr != nil {
		export.Status = ExportStatusFailed
		export.Error = processErr.Error()
	} else {
		export.Status = ExportStatusCompleted
		export.Progress = 100
	}
	s.repo.Update(ctx, export)
}

// processFullAuditExport processes a full audit export.
func (s *ExportService) processFullAuditExport(ctx context.Context, export *Export) error {
	// Update progress
	export.Progress = 10
	s.repo.Update(ctx, export)

	// TODO: Query audit data from database
	// This will be implemented when integrated with the full system

	export.Progress = 50
	s.repo.Update(ctx, export)

	// TODO: Generate export file in requested format

	export.Progress = 90
	export.RecordCount = 0 // Will be set from actual data
	s.repo.Update(ctx, export)

	return nil
}

// processConformityExport processes a conformity evidence export.
func (s *ExportService) processConformityExport(ctx context.Context, export *Export) error {
	export.Progress = 50
	s.repo.Update(ctx, export)
	// TODO: Implement conformity export
	return nil
}

// processHITLExport processes a HITL summary export.
func (s *ExportService) processHITLExport(ctx context.Context, export *Export) error {
	export.Progress = 50
	s.repo.Update(ctx, export)
	// TODO: Implement HITL export
	return nil
}

// processDecisionChainExport processes a decision chain export.
func (s *ExportService) processDecisionChainExport(ctx context.Context, export *Export) error {
	export.Progress = 50
	s.repo.Update(ctx, export)
	// TODO: Implement decision chain export
	return nil
}

// processPolicyViolationsExport processes a policy violations export.
func (s *ExportService) processPolicyViolationsExport(ctx context.Context, export *Export) error {
	export.Progress = 50
	s.repo.Update(ctx, export)
	// TODO: Implement policy violations export
	return nil
}

// processAccuracyExport processes an accuracy metrics export.
func (s *ExportService) processAccuracyExport(ctx context.Context, export *Export) error {
	export.Progress = 50
	s.repo.Update(ctx, export)
	// TODO: Implement accuracy export
	return nil
}
