// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"bytes"
	"context"
	"encoding/json"
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

// GetExportDownloadURL generates a presigned download URL for a completed export
// OWNED BY orgID. If the export has a StorageKey and a storage backend is
// configured, it returns a time-limited presigned URL. Otherwise it returns an
// empty string.
//
// orgID is required (#3241): without it this minted a presigned URL for any
// export id, which is a download of another organization's compliance evidence
// over a link that then works for anyone who holds it.
func (s *ExportService) GetExportDownloadURL(ctx context.Context, orgID, exportID string) (string, error) {
	export, err := s.repo.GetByID(ctx, orgID, exportID)
	if err != nil {
		return "", fmt.Errorf("get export: %w", err)
	}
	if export == nil {
		return "", ErrExportNotFound
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

	// Start async export processing. The organization travels WITH the id: the
	// processor re-reads the row, and an unscoped re-read is the same by-id
	// hole this change closes on the request path (#3241).
	go s.processExport(export.OrgID, export.ID)

	return &result, nil
}

// GetExport retrieves an export by ID within an organization.
func (s *ExportService) GetExport(ctx context.Context, orgID, id string) (*Export, error) {
	return s.repo.GetByID(ctx, orgID, id)
}

// ListExports retrieves exports for an organization.
func (s *ExportService) ListExports(ctx context.Context, orgID string, limit, offset int) ([]*Export, int64, error) {
	return s.repo.List(ctx, orgID, limit, offset)
}

// processExport processes an export job asynchronously.
func (s *ExportService) processExport(orgID, exportID string) {
	ctx := context.Background()

	export, err := s.repo.GetByID(ctx, orgID, exportID)
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

// finalizeExportPayload records the true row count + serialized size on the
// export and — when a cloud storage backend is configured — uploads the JSON
// payload so the export is downloadable. It mirrors the decision-chain upload
// path so every EU AI Act export type shares identical storage semantics and
// the same JSON-only delivery limitation (CSV/XML/PDF rendering is not yet
// implemented for any export type). When no storage backend is configured the
// record count + file size still reflect the real rows; the export is produced
// but not downloadable — the same limitation the decision-chain export carries.
// slug is the storage-key/file basename for the export type. #2610.
func (s *ExportService) finalizeExportPayload(ctx context.Context, export *Export, recordCount int, payload []byte, slug string) error {
	export.RecordCount = recordCount
	export.FileSize = int64(len(payload))

	if s.storageBackend == nil {
		return nil
	}
	storageKey := fmt.Sprintf("euaiact/%s/%s-%s.json", export.OrgID, slug, export.ID)
	if _, err := s.storageBackend.Upload(ctx, &cloudstorage.UploadRequest{
		Key:         storageKey,
		Body:        bytes.NewReader(payload),
		ContentType: "application/json",
		Metadata: map[string]string{
			"export_id":   export.ID,
			"org_id":      export.OrgID,
			"export_type": string(export.ExportType),
		},
	}); err != nil {
		return fmt.Errorf("upload %s export: %w", slug, err)
	}
	export.StorageType = "cloud"
	export.StorageKey = storageKey
	return nil
}

// processFullAuditExport processes a full audit export — the canonical
// audit_logs record set (every governed request/response, not just the
// decision-only subset) for the org + window, for EU AI Act Article 12
// record-keeping. It queries the real rows, records the true count, and uploads
// the serialized payload when a storage backend is configured. An empty window
// yields a truthful zero-record export (a regulator-valid "no governed activity
// in range" attestation), never a fabricated success (#2591) — only a genuine
// query/serialize/upload error fails the job. #2610.
func (s *ExportService) processFullAuditExport(ctx context.Context, export *Export) error {
	export.Progress = 25
	s.repo.Update(ctx, export)

	records, err := s.repo.GetFullAudit(ctx, export.OrgID, export.DateFrom, export.DateTo)
	if err != nil {
		return fmt.Errorf("query full audit: %w", err)
	}

	export.Progress = 60
	s.repo.Update(ctx, export)

	payload, err := json.Marshal(map[string]interface{}{
		"export_id":    export.ID,
		"org_id":       export.OrgID,
		"export_type":  export.ExportType,
		"date_from":    export.DateFrom,
		"date_to":      export.DateTo,
		"record_count": len(records),
		"audit_logs":   records,
	})
	if err != nil {
		return fmt.Errorf("marshal full audit: %w", err)
	}

	if err := s.finalizeExportPayload(ctx, export, len(records), payload, "full-audit"); err != nil {
		return err
	}
	export.Progress = 90
	s.repo.Update(ctx, export)
	return nil
}

// processConformityExport processes a conformity evidence export — the
// euaiact_conformity_assessments (Article 43) for the org whose assessment_date
// falls in the window, with their full requirements/evidence/findings content.
// Real data, true count, fail-on-error (#2591). #2610.
func (s *ExportService) processConformityExport(ctx context.Context, export *Export) error {
	export.Progress = 25
	s.repo.Update(ctx, export)

	assessments, err := s.repo.GetConformityAssessments(ctx, export.OrgID, export.DateFrom, export.DateTo)
	if err != nil {
		return fmt.Errorf("query conformity assessments: %w", err)
	}

	export.Progress = 60
	s.repo.Update(ctx, export)

	payload, err := json.Marshal(map[string]interface{}{
		"export_id":              export.ID,
		"org_id":                 export.OrgID,
		"export_type":            export.ExportType,
		"date_from":              export.DateFrom,
		"date_to":                export.DateTo,
		"record_count":           len(assessments),
		"conformity_assessments": assessments,
	})
	if err != nil {
		return fmt.Errorf("marshal conformity assessments: %w", err)
	}

	if err := s.finalizeExportPayload(ctx, export, len(assessments), payload, "conformity-evidence"); err != nil {
		return err
	}
	export.Progress = 90
	s.repo.Update(ctx, export)
	return nil
}

// processHITLExport processes a HITL summary export — the hitl_approval_history
// immutable human-oversight audit trail (Article 14 oversight / Article 12
// record-keeping) for the org + window. Real data, true count, fail-on-error
// (#2591). #2610.
func (s *ExportService) processHITLExport(ctx context.Context, export *Export) error {
	export.Progress = 25
	s.repo.Update(ctx, export)

	records, err := s.repo.GetHITLApprovalHistory(ctx, export.OrgID, export.DateFrom, export.DateTo)
	if err != nil {
		return fmt.Errorf("query HITL approval history: %w", err)
	}

	export.Progress = 60
	s.repo.Update(ctx, export)

	payload, err := json.Marshal(map[string]interface{}{
		"export_id":      export.ID,
		"org_id":         export.OrgID,
		"export_type":    export.ExportType,
		"date_from":      export.DateFrom,
		"date_to":        export.DateTo,
		"record_count":   len(records),
		"hitl_approvals": records,
	})
	if err != nil {
		return fmt.Errorf("marshal HITL approval history: %w", err)
	}

	if err := s.finalizeExportPayload(ctx, export, len(records), payload, "hitl-summary"); err != nil {
		return err
	}
	export.Progress = 90
	s.repo.Update(ctx, export)
	return nil
}

// processDecisionChainExport processes a decision_chain export — the
// per-decision audit rows for the requested org + window, reconstructed into
// logical chains: rows sharing a correlation_id (the W3C trace_id a PEP
// propagates across its hops) are grouped into one chain in step order, rows
// without one are singletons (#2598). The payload carries both the flat
// chronological list (decision_chain) and the grouped view (decision_chains).
//
// The rows are derived from the canonical audit_logs decision rows (#2588); the
// legacy decision_chain table this export was conceptually tied to has no live
// writer, so this processor previously returned an empty (RecordCount=0) export
// in every deployment. It now queries the real rows, records the true count
// (decision records / steps), and — when a cloud storage backend is configured —
// uploads the serialized payload so it is downloadable. The payload is JSON
// regardless of the requested format (CSV/XML/PDF rendering is not yet
// implemented for any EU AI Act export type); the storage key reflects this with
// a .json suffix.
func (s *ExportService) processDecisionChainExport(ctx context.Context, export *Export) error {
	export.Progress = 25
	s.repo.Update(ctx, export)

	records, err := s.repo.GetDecisionChain(ctx, export.OrgID, export.DateFrom, export.DateTo)
	if err != nil {
		return fmt.Errorf("query decision chain: %w", err)
	}

	chains := groupDecisionChain(records)

	// RecordCount stays the decision-record (step) count for retention/volume
	// reporting; chain_count reports how many logical chains those steps formed.
	export.RecordCount = len(records)
	export.Progress = 60
	s.repo.Update(ctx, export)

	payload, err := json.Marshal(map[string]interface{}{
		"export_id":       export.ID,
		"org_id":          export.OrgID,
		"export_type":     export.ExportType,
		"date_from":       export.DateFrom,
		"date_to":         export.DateTo,
		"record_count":    len(records),
		"chain_count":     len(chains),
		"decision_chain":  records,
		"decision_chains": chains,
	})
	if err != nil {
		return fmt.Errorf("marshal decision chain: %w", err)
	}
	export.FileSize = int64(len(payload))

	// Persist the payload so the export is downloadable. Mirrors the SEBI cloud
	// upload path; when no storage backend is configured the record count + file
	// size still reflect the real decision rows (same delivery limitation the
	// other EU AI Act export types carry).
	if s.storageBackend != nil {
		storageKey := fmt.Sprintf("euaiact/%s/decision-chain-%s.json", export.OrgID, export.ID)
		if _, upErr := s.storageBackend.Upload(ctx, &cloudstorage.UploadRequest{
			Key:         storageKey,
			Body:        bytes.NewReader(payload),
			ContentType: "application/json",
			Metadata: map[string]string{
				"export_id":   export.ID,
				"org_id":      export.OrgID,
				"export_type": string(export.ExportType),
			},
		}); upErr != nil {
			return fmt.Errorf("upload decision chain export: %w", upErr)
		}
		export.StorageType = "cloud"
		export.StorageKey = storageKey
	}

	export.Progress = 90
	s.repo.Update(ctx, export)
	return nil
}

// processPolicyViolationsExport processes a policy violations export — the
// policy_violations rows for the org + window (Article 12 record-keeping /
// Article 9 risk-management evidence). Real data, true count, fail-on-error
// (#2591). #2610.
func (s *ExportService) processPolicyViolationsExport(ctx context.Context, export *Export) error {
	export.Progress = 25
	s.repo.Update(ctx, export)

	records, err := s.repo.GetPolicyViolations(ctx, export.OrgID, export.DateFrom, export.DateTo)
	if err != nil {
		return fmt.Errorf("query policy violations: %w", err)
	}

	export.Progress = 60
	s.repo.Update(ctx, export)

	payload, err := json.Marshal(map[string]interface{}{
		"export_id":         export.ID,
		"org_id":            export.OrgID,
		"export_type":       export.ExportType,
		"date_from":         export.DateFrom,
		"date_to":           export.DateTo,
		"record_count":      len(records),
		"policy_violations": records,
	})
	if err != nil {
		return fmt.Errorf("marshal policy violations: %w", err)
	}

	if err := s.finalizeExportPayload(ctx, export, len(records), payload, "policy-violations"); err != nil {
		return err
	}
	export.Progress = 90
	s.repo.Update(ctx, export)
	return nil
}

// processAccuracyExport processes an accuracy metrics export — the
// euaiact_accuracy_metrics rows for the org + window (Article 15 accuracy
// record-keeping). Real data, true count, fail-on-error (#2591). #2610.
func (s *ExportService) processAccuracyExport(ctx context.Context, export *Export) error {
	export.Progress = 25
	s.repo.Update(ctx, export)

	metrics, err := s.repo.GetAccuracyMetrics(ctx, export.OrgID, export.DateFrom, export.DateTo)
	if err != nil {
		return fmt.Errorf("query accuracy metrics: %w", err)
	}

	export.Progress = 60
	s.repo.Update(ctx, export)

	payload, err := json.Marshal(map[string]interface{}{
		"export_id":        export.ID,
		"org_id":           export.OrgID,
		"export_type":      export.ExportType,
		"date_from":        export.DateFrom,
		"date_to":          export.DateTo,
		"record_count":     len(metrics),
		"accuracy_metrics": metrics,
	})
	if err != nil {
		return fmt.Errorf("marshal accuracy metrics: %w", err)
	}

	if err := s.finalizeExportPayload(ctx, export, len(metrics), payload, "accuracy-metrics"); err != nil {
		return err
	}
	export.Progress = 90
	s.repo.Update(ctx, export)
	return nil
}
