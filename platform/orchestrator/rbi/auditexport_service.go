// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"axonflow/platform/orchestrator/cloudstorage"
)

// AuditExportService provides business logic for audit exports.
type AuditExportService struct {
	repo           AuditExportRepository
	systemRepo     AISystemRepository
	validationRepo ModelValidationRepository
	incidentRepo   AIIncidentRepository
	killSwitchRepo KillSwitchRepository
	reportRepo     BoardReportRepository
	exportBasePath string
	storageBackend cloudstorage.StorageBackend // nil = local filesystem (backward compat)
}

// NewAuditExportService creates a new audit export service.
func NewAuditExportService(
	repo AuditExportRepository,
	systemRepo AISystemRepository,
	validationRepo ModelValidationRepository,
	incidentRepo AIIncidentRepository,
	killSwitchRepo KillSwitchRepository,
	reportRepo BoardReportRepository,
	exportBasePath string,
	storageBackend cloudstorage.StorageBackend,
) *AuditExportService {
	if exportBasePath == "" {
		exportBasePath = "/tmp/rbi-audit-exports"
	}
	return &AuditExportService{
		repo:           repo,
		systemRepo:     systemRepo,
		validationRepo: validationRepo,
		incidentRepo:   incidentRepo,
		killSwitchRepo: killSwitchRepo,
		reportRepo:     reportRepo,
		exportBasePath: exportBasePath,
		storageBackend: storageBackend,
	}
}

// CreateExportRequest represents a request to create an audit export.
type CreateExportRequest struct {
	OrgID            string
	ExportType       AuditExportType
	Format           AuditExportFormat
	StartDate        *time.Time
	EndDate          *time.Time
	SystemIDs        []string
	RiskCategories   []string
	IncludeArchived  bool
	RequestedBy      string
	RequestedByEmail string
	Purpose          string
}

// CreateExport creates a new audit export request.
func (s *AuditExportService) CreateExport(ctx context.Context, req *CreateExportRequest) (*AuditExport, error) {
	if req.OrgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	if !req.ExportType.Valid() {
		return nil, fmt.Errorf("invalid export type: %s", req.ExportType)
	}
	if !req.Format.Valid() {
		return nil, fmt.Errorf("invalid format: %s", req.Format)
	}

	export := &AuditExport{
		OrgID:            req.OrgID,
		ExportType:       req.ExportType,
		Format:           req.Format,
		StartDate:        req.StartDate,
		EndDate:          req.EndDate,
		SystemIDs:        req.SystemIDs,
		RiskCategories:   req.RiskCategories,
		IncludeArchived:  req.IncludeArchived,
		Status:           AuditExportStatusPending,
		RequestedBy:      req.RequestedBy,
		RequestedByEmail: req.RequestedByEmail,
		Purpose:          req.Purpose,
	}

	if err := s.repo.Create(ctx, export); err != nil {
		return nil, fmt.Errorf("failed to create export: %w", err)
	}

	return export, nil
}

// GetExport retrieves an audit export by ID.
func (s *AuditExportService) GetExport(ctx context.Context, orgID, id string) (*AuditExport, error) {
	return s.repo.Get(ctx, orgID, id)
}

// ListExports retrieves audit exports with optional filtering.
func (s *AuditExportService) ListExports(ctx context.Context, orgID string, params *ListAuditExportsParams) ([]*AuditExport, int, error) {
	return s.repo.List(ctx, orgID, params)
}

// DeleteExport deletes an audit export and its associated file.
func (s *AuditExportService) DeleteExport(ctx context.Context, orgID, id string) error {
	export, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return err
	}

	// Delete the file from cloud or local storage
	if export.StorageKey != "" && s.storageBackend != nil {
		if delErr := s.storageBackend.Delete(ctx, export.StorageKey); delErr != nil {
			log.Printf("[RBIAudit] Warning: failed to delete cloud object %s: %v", export.StorageKey, delErr)
		}
	} else if export.FilePath != "" && !strings.HasPrefix(export.FilePath, "cloud://") {
		os.Remove(export.FilePath)
	}

	return s.repo.Delete(ctx, orgID, id)
}

// ProcessExport processes a pending audit export.
func (s *AuditExportService) ProcessExport(ctx context.Context, export *AuditExport) error {
	// Mark as processing
	now := time.Now().UTC()
	export.Status = AuditExportStatusProcessing
	export.StartedAt = &now
	if err := s.repo.Update(ctx, export); err != nil {
		return fmt.Errorf("failed to update export status: %w", err)
	}

	// Collect data
	data, err := s.collectExportData(ctx, export)
	if err != nil {
		export.Status = AuditExportStatusFailed
		export.ErrorMessage = err.Error()
		s.repo.Update(ctx, export)
		return fmt.Errorf("failed to collect export data: %w", err)
	}

	// Generate file
	filePath, fileSize, checksum, err := s.generateExportFile(export, data)
	if err != nil {
		export.Status = AuditExportStatusFailed
		export.ErrorMessage = err.Error()
		s.repo.Update(ctx, export)
		return fmt.Errorf("failed to generate export file: %w", err)
	}

	// Upload to cloud storage if configured
	if s.storageBackend != nil {
		storageKey := fmt.Sprintf("%s/rbi-audit-%s-%s.%s",
			export.OrgID, export.ExportType,
			time.Now().UTC().Format("20060102-150405"), export.Format)

		content, readErr := os.ReadFile(filePath)
		if readErr != nil {
			export.Status = AuditExportStatusFailed
			export.ErrorMessage = readErr.Error()
			s.repo.Update(ctx, export)
			return fmt.Errorf("failed to read export file for upload: %w", readErr)
		}

		contentType := "application/octet-stream"
		switch export.Format {
		case AuditExportFormatJSON:
			contentType = "application/json"
		case AuditExportFormatCSV:
			contentType = "text/csv"
		case AuditExportFormatPDF:
			contentType = "application/pdf"
		}

		_, uploadErr := s.storageBackend.Upload(ctx, &cloudstorage.UploadRequest{
			Key:         storageKey,
			Body:        bytes.NewReader(content),
			ContentType: contentType,
			Metadata: map[string]string{
				"export_id":  export.ID,
				"org_id":     export.OrgID,
				"export_type": string(export.ExportType),
				"checksum":   checksum,
			},
		})
		if uploadErr != nil {
			export.Status = AuditExportStatusFailed
			export.ErrorMessage = uploadErr.Error()
			s.repo.Update(ctx, export)
			return fmt.Errorf("failed to upload export to cloud storage: %w", uploadErr)
		}

		// Clean up local temp file
		os.Remove(filePath)

		// Use cloud path — presigned URLs are generated on-demand via
		// GetExportDownloadURL, not stored in the database (they expire)
		filePath = "cloud://" + storageKey
		export.StorageKey = storageKey
		export.StorageType = s.storageBackend.Type()
	} else {
		export.StorageType = "local"
	}

	// Update export with results
	completedAt := time.Now().UTC()
	expiresAt := completedAt.Add(7 * 24 * time.Hour) // 7 days retention
	export.Status = AuditExportStatusCompleted
	export.CompletedAt = &completedAt
	export.FilePath = filePath
	export.FileSizeBytes = fileSize
	export.FileChecksum = checksum
	export.RecordCount = data.TotalRecords
	export.Summary = data.Summary
	export.ExpiresAt = &expiresAt

	if err := s.repo.Update(ctx, export); err != nil {
		return fmt.Errorf("failed to update export results: %w", err)
	}

	return nil
}

// ExportData holds the collected data for an export.
type ExportData struct {
	Systems      []*AISystem        `json:"systems,omitempty"`
	Validations  []*ModelValidation `json:"validations,omitempty"`
	Incidents    []*AIIncident      `json:"incidents,omitempty"`
	KillSwitches []*KillSwitch      `json:"kill_switches,omitempty"`
	Reports      []*BoardReport     `json:"reports,omitempty"`
	TotalRecords int                `json:"total_records"`
	Summary      *AuditExportSummary `json:"summary"`
	ExportMeta   *ExportMetadata    `json:"export_metadata"`
}

// ExportMetadata contains metadata about the export.
type ExportMetadata struct {
	ExportID      string     `json:"export_id"`
	OrgID         string     `json:"org_id"`
	ExportType    string     `json:"export_type"`
	Format        string     `json:"format"`
	StartDate     *time.Time `json:"start_date,omitempty"`
	EndDate       *time.Time `json:"end_date,omitempty"`
	GeneratedAt   time.Time  `json:"generated_at"`
	GeneratedBy   string     `json:"generated_by,omitempty"`
	Purpose       string     `json:"purpose,omitempty"`
}

func (s *AuditExportService) collectExportData(ctx context.Context, export *AuditExport) (*ExportData, error) {
	data := &ExportData{
		Summary: &AuditExportSummary{},
		ExportMeta: &ExportMetadata{
			ExportID:    export.ID,
			OrgID:       export.OrgID,
			ExportType:  string(export.ExportType),
			Format:      string(export.Format),
			StartDate:   export.StartDate,
			EndDate:     export.EndDate,
			GeneratedAt: time.Now().UTC(),
			GeneratedBy: export.RequestedBy,
			Purpose:     export.Purpose,
		},
	}

	var err error

	switch export.ExportType {
	case AuditExportTypeFull, AuditExportTypeComprehensive:
		err = s.collectAllData(ctx, export, data)
	case AuditExportTypeSystems:
		err = s.collectSystemsData(ctx, export, data)
	case AuditExportTypeValidations:
		err = s.collectValidationsData(ctx, export, data)
	case AuditExportTypeIncidents:
		err = s.collectIncidentsData(ctx, export, data)
	case AuditExportTypeKillSwitches:
		err = s.collectKillSwitchesData(ctx, export, data)
	case AuditExportTypeReports:
		err = s.collectReportsData(ctx, export, data)
	default:
		return nil, fmt.Errorf("unsupported export type: %s", export.ExportType)
	}

	if err != nil {
		return nil, err
	}

	// Calculate total records
	data.TotalRecords = len(data.Systems) + len(data.Validations) +
		len(data.Incidents) + len(data.KillSwitches) + len(data.Reports)

	return data, nil
}

func (s *AuditExportService) collectAllData(ctx context.Context, export *AuditExport, data *ExportData) error {
	if err := s.collectSystemsData(ctx, export, data); err != nil {
		return err
	}
	if err := s.collectValidationsData(ctx, export, data); err != nil {
		return err
	}
	if err := s.collectIncidentsData(ctx, export, data); err != nil {
		return err
	}
	if err := s.collectKillSwitchesData(ctx, export, data); err != nil {
		return err
	}
	if err := s.collectReportsData(ctx, export, data); err != nil {
		return err
	}
	return nil
}

func (s *AuditExportService) collectSystemsData(ctx context.Context, export *AuditExport, data *ExportData) error {
	if s.systemRepo == nil {
		return nil
	}

	params := &ListAISystemsParams{
		Limit: 1000, // Get all systems
	}

	// Filter by risk categories if specified
	if len(export.RiskCategories) > 0 {
		params.RiskCategory = export.RiskCategories[0] // Use first one for now
	}

	systems, _, err := s.systemRepo.List(ctx, export.OrgID, params)
	if err != nil {
		return fmt.Errorf("failed to fetch systems: %w", err)
	}

	// Filter by system IDs if specified
	if len(export.SystemIDs) > 0 {
		systemIDSet := make(map[string]bool)
		for _, id := range export.SystemIDs {
			systemIDSet[id] = true
		}
		var filtered []*AISystem
		for _, sys := range systems {
			if systemIDSet[sys.ID] {
				filtered = append(filtered, sys)
			}
		}
		systems = filtered
	}

	// Filter by date range if specified
	if export.StartDate != nil || export.EndDate != nil {
		var filtered []*AISystem
		for _, sys := range systems {
			if export.StartDate != nil && sys.CreatedAt.Before(*export.StartDate) {
				continue
			}
			if export.EndDate != nil && sys.CreatedAt.After(*export.EndDate) {
				continue
			}
			filtered = append(filtered, sys)
		}
		systems = filtered
	}

	// Filter deprecated if not including archived
	if !export.IncludeArchived {
		var filtered []*AISystem
		for _, sys := range systems {
			if sys.DeploymentStatus != DeploymentStatusDeprecated {
				filtered = append(filtered, sys)
			}
		}
		systems = filtered
	}

	data.Systems = systems
	data.Summary.TotalSystems = len(systems)

	return nil
}

func (s *AuditExportService) collectValidationsData(ctx context.Context, export *AuditExport, data *ExportData) error {
	if s.validationRepo == nil {
		return nil
	}

	params := &ListValidationsParams{
		Limit: 1000,
	}

	// Filter by system IDs if specified
	if len(export.SystemIDs) == 1 {
		params.SystemID = export.SystemIDs[0]
	}

	validations, _, err := s.validationRepo.List(ctx, export.OrgID, params)
	if err != nil {
		return fmt.Errorf("failed to fetch validations: %w", err)
	}

	// Filter by multiple system IDs if specified
	if len(export.SystemIDs) > 1 {
		systemIDSet := make(map[string]bool)
		for _, id := range export.SystemIDs {
			systemIDSet[id] = true
		}
		var filtered []*ModelValidation
		for _, val := range validations {
			if systemIDSet[val.SystemID] {
				filtered = append(filtered, val)
			}
		}
		validations = filtered
	}

	// Filter by date range
	if export.StartDate != nil || export.EndDate != nil {
		var filtered []*ModelValidation
		for _, val := range validations {
			if export.StartDate != nil && val.CreatedAt.Before(*export.StartDate) {
				continue
			}
			if export.EndDate != nil && val.CreatedAt.After(*export.EndDate) {
				continue
			}
			filtered = append(filtered, val)
		}
		validations = filtered
	}

	data.Validations = validations
	data.Summary.TotalValidations = len(validations)

	return nil
}

func (s *AuditExportService) collectIncidentsData(ctx context.Context, export *AuditExport, data *ExportData) error {
	if s.incidentRepo == nil {
		return nil
	}

	params := &ListIncidentsParams{
		Limit: 1000,
	}

	// Filter by system IDs if specified
	if len(export.SystemIDs) == 1 {
		params.SystemID = export.SystemIDs[0]
	}

	incidents, _, err := s.incidentRepo.List(ctx, export.OrgID, params)
	if err != nil {
		return fmt.Errorf("failed to fetch incidents: %w", err)
	}

	// Filter by multiple system IDs if specified
	if len(export.SystemIDs) > 1 {
		systemIDSet := make(map[string]bool)
		for _, id := range export.SystemIDs {
			systemIDSet[id] = true
		}
		var filtered []*AIIncident
		for _, inc := range incidents {
			if systemIDSet[inc.SystemID] {
				filtered = append(filtered, inc)
			}
		}
		incidents = filtered
	}

	// Filter by date range
	if export.StartDate != nil || export.EndDate != nil {
		var filtered []*AIIncident
		for _, inc := range incidents {
			if export.StartDate != nil && inc.CreatedAt.Before(*export.StartDate) {
				continue
			}
			if export.EndDate != nil && inc.CreatedAt.After(*export.EndDate) {
				continue
			}
			filtered = append(filtered, inc)
		}
		incidents = filtered
	}

	data.Incidents = incidents
	data.Summary.TotalIncidents = len(incidents)

	return nil
}

func (s *AuditExportService) collectKillSwitchesData(ctx context.Context, export *AuditExport, data *ExportData) error {
	if s.killSwitchRepo == nil {
		return nil
	}

	params := &ListKillSwitchParams{
		Limit: 1000,
	}

	killSwitches, _, err := s.killSwitchRepo.List(ctx, export.OrgID, params)
	if err != nil {
		return fmt.Errorf("failed to fetch kill switches: %w", err)
	}

	// Filter by system IDs if specified
	if len(export.SystemIDs) > 0 {
		systemIDSet := make(map[string]bool)
		for _, id := range export.SystemIDs {
			systemIDSet[id] = true
		}
		var filtered []*KillSwitch
		for _, ks := range killSwitches {
			// Include global kill switches or those matching system IDs
			if ks.Scope == KillSwitchScopeGlobal || systemIDSet[ks.SystemID] {
				filtered = append(filtered, ks)
			}
		}
		killSwitches = filtered
	}

	// Filter by date range
	if export.StartDate != nil || export.EndDate != nil {
		var filtered []*KillSwitch
		for _, ks := range killSwitches {
			if export.StartDate != nil && ks.CreatedAt.Before(*export.StartDate) {
				continue
			}
			if export.EndDate != nil && ks.CreatedAt.After(*export.EndDate) {
				continue
			}
			filtered = append(filtered, ks)
		}
		killSwitches = filtered
	}

	data.KillSwitches = killSwitches
	data.Summary.TotalKillSwitches = len(killSwitches)

	return nil
}

func (s *AuditExportService) collectReportsData(ctx context.Context, export *AuditExport, data *ExportData) error {
	if s.reportRepo == nil {
		return nil
	}

	params := &ListBoardReportsParams{
		Limit: 1000,
	}

	reports, _, err := s.reportRepo.List(ctx, export.OrgID, params)
	if err != nil {
		return fmt.Errorf("failed to fetch reports: %w", err)
	}

	// Filter by date range
	if export.StartDate != nil || export.EndDate != nil {
		var filtered []*BoardReport
		for _, rpt := range reports {
			if export.StartDate != nil && rpt.CreatedAt.Before(*export.StartDate) {
				continue
			}
			if export.EndDate != nil && rpt.CreatedAt.After(*export.EndDate) {
				continue
			}
			filtered = append(filtered, rpt)
		}
		reports = filtered
	}

	data.Reports = reports
	data.Summary.TotalReports = len(reports)

	return nil
}

func (s *AuditExportService) generateExportFile(export *AuditExport, data *ExportData) (string, int64, string, error) {
	// Ensure export directory exists
	exportDir := filepath.Join(s.exportBasePath, export.OrgID)
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return "", 0, "", fmt.Errorf("failed to create export directory: %w", err)
	}

	// Generate filename
	timestamp := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("rbi-audit-%s-%s.%s", export.ExportType, timestamp, export.Format)
	filePath := filepath.Join(exportDir, filename)

	var err error
	switch export.Format {
	case AuditExportFormatJSON:
		err = s.generateJSONFile(filePath, data)
	case AuditExportFormatCSV:
		err = s.generateCSVFile(filePath, data)
	case AuditExportFormatPDF:
		err = s.generatePDFFile(filePath, data)
	case AuditExportFormatXLSX:
		err = s.generateXLSXFile(filePath, data)
	default:
		return "", 0, "", fmt.Errorf("unsupported format: %s", export.Format)
	}

	if err != nil {
		return "", 0, "", err
	}

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to stat export file: %w", err)
	}

	// Calculate checksum
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to read export file: %w", err)
	}
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])

	return filePath, fileInfo.Size(), checksum, nil
}

func (s *AuditExportService) generateJSONFile(filePath string, data *ExportData) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

func (s *AuditExportService) generateCSVFile(filePath string, data *ExportData) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write metadata header
	writer.Write([]string{"# RBI Audit Export"})
	writer.Write([]string{"# Export ID:", data.ExportMeta.ExportID})
	writer.Write([]string{"# Generated At:", data.ExportMeta.GeneratedAt.Format(time.RFC3339)})
	writer.Write([]string{"# Type:", data.ExportMeta.ExportType})
	writer.Write([]string{""})

	// Write systems
	if len(data.Systems) > 0 {
		writer.Write([]string{"## AI Systems"})
		writer.Write([]string{"ID", "System Name", "Description", "Risk Category", "Deployment Status", "Created At"})
		for _, sys := range data.Systems {
			writer.Write([]string{
				sys.ID,
				sys.SystemName,
				sys.Description,
				string(sys.RiskCategory),
				string(sys.DeploymentStatus),
				sys.CreatedAt.Format(time.RFC3339),
			})
		}
		writer.Write([]string{""})
	}

	// Write validations
	if len(data.Validations) > 0 {
		writer.Write([]string{"## Model Validations"})
		writer.Write([]string{"ID", "System ID", "Validator Name", "Validation Type", "Recommendation", "Created At"})
		for _, val := range data.Validations {
			writer.Write([]string{
				val.ID,
				val.SystemID,
				val.ValidatorName,
				string(val.ValidationType),
				string(val.Recommendation),
				val.CreatedAt.Format(time.RFC3339),
			})
		}
		writer.Write([]string{""})
	}

	// Write incidents
	if len(data.Incidents) > 0 {
		writer.Write([]string{"## Incidents"})
		writer.Write([]string{"ID", "System ID", "Title", "Severity", "Status", "Created At"})
		for _, inc := range data.Incidents {
			writer.Write([]string{
				inc.ID,
				inc.SystemID,
				inc.Title,
				string(inc.Severity),
				string(inc.Status),
				inc.CreatedAt.Format(time.RFC3339),
			})
		}
		writer.Write([]string{""})
	}

	// Write kill switches
	if len(data.KillSwitches) > 0 {
		writer.Write([]string{"## Kill Switches"})
		writer.Write([]string{"ID", "Scope", "System ID", "Activation Reason", "Is Active", "Created At"})
		for _, ks := range data.KillSwitches {
			activeStr := "false"
			if ks.IsActive {
				activeStr = "true"
			}
			writer.Write([]string{
				ks.ID,
				string(ks.Scope),
				ks.SystemID,
				ks.ActivationReason,
				activeStr,
				ks.CreatedAt.Format(time.RFC3339),
			})
		}
		writer.Write([]string{""})
	}

	// Write reports
	if len(data.Reports) > 0 {
		writer.Write([]string{"## Board Reports"})
		writer.Write([]string{"ID", "Report Type", "Period Start", "Period End", "Approval Status", "Created At"})
		for _, rpt := range data.Reports {
			periodStart := ""
			periodEnd := ""
			if rpt.ReportPeriodStart != nil {
				periodStart = rpt.ReportPeriodStart.Format("2006-01-02")
			}
			if rpt.ReportPeriodEnd != nil {
				periodEnd = rpt.ReportPeriodEnd.Format("2006-01-02")
			}
			writer.Write([]string{
				rpt.ID,
				string(rpt.ReportType),
				periodStart,
				periodEnd,
				string(rpt.ApprovalStatus),
				rpt.CreatedAt.Format(time.RFC3339),
			})
		}
	}

	// Write summary
	writer.Write([]string{""})
	writer.Write([]string{"## Summary"})
	writer.Write([]string{"Total Systems:", fmt.Sprintf("%d", data.Summary.TotalSystems)})
	writer.Write([]string{"Total Validations:", fmt.Sprintf("%d", data.Summary.TotalValidations)})
	writer.Write([]string{"Total Incidents:", fmt.Sprintf("%d", data.Summary.TotalIncidents)})
	writer.Write([]string{"Total Kill Switches:", fmt.Sprintf("%d", data.Summary.TotalKillSwitches)})
	writer.Write([]string{"Total Reports:", fmt.Sprintf("%d", data.Summary.TotalReports)})

	return nil
}

func (s *AuditExportService) generatePDFFile(filePath string, data *ExportData) error {
	// For now, generate a text-based placeholder that could be converted to PDF
	// In production, use a proper PDF library like gofpdf or wkhtmltopdf
	textPath := strings.TrimSuffix(filePath, ".pdf") + ".txt"

	file, err := os.Create(textPath)
	if err != nil {
		return fmt.Errorf("failed to create PDF placeholder: %w", err)
	}
	defer file.Close()

	// Write content
	fmt.Fprintf(file, "RBI FREE-AI FRAMEWORK AUDIT REPORT\n")
	fmt.Fprintf(file, "===================================\n\n")
	fmt.Fprintf(file, "Export ID: %s\n", data.ExportMeta.ExportID)
	fmt.Fprintf(file, "Organization: %s\n", data.ExportMeta.OrgID)
	fmt.Fprintf(file, "Generated: %s\n", data.ExportMeta.GeneratedAt.Format(time.RFC1123))
	fmt.Fprintf(file, "Purpose: %s\n\n", data.ExportMeta.Purpose)

	fmt.Fprintf(file, "SUMMARY\n")
	fmt.Fprintf(file, "-------\n")
	fmt.Fprintf(file, "AI Systems: %d\n", data.Summary.TotalSystems)
	fmt.Fprintf(file, "Model Validations: %d\n", data.Summary.TotalValidations)
	fmt.Fprintf(file, "Incidents: %d\n", data.Summary.TotalIncidents)
	fmt.Fprintf(file, "Kill Switches: %d\n", data.Summary.TotalKillSwitches)
	fmt.Fprintf(file, "Board Reports: %d\n\n", data.Summary.TotalReports)

	// Rename to .pdf (placeholder)
	os.Rename(textPath, filePath)

	return nil
}

func (s *AuditExportService) generateXLSXFile(filePath string, data *ExportData) error {
	// For now, generate CSV as placeholder for XLSX
	// In production, use excelize library
	return s.generateCSVFile(filePath, data)
}

// GetExportFile retrieves the export file content.
func (s *AuditExportService) GetExportFile(ctx context.Context, orgID, id string) ([]byte, string, error) {
	export, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, "", err
	}

	if export.Status != AuditExportStatusCompleted {
		return nil, "", fmt.Errorf("export not completed, status: %s", export.Status)
	}

	if export.FilePath == "" {
		return nil, "", fmt.Errorf("export file not available")
	}

	var content []byte

	if strings.HasPrefix(export.FilePath, "cloud://") {
		// Download from cloud storage
		if s.storageBackend == nil {
			return nil, "", fmt.Errorf("cloud storage backend not configured")
		}
		reader, dlErr := s.storageBackend.Download(ctx, export.StorageKey)
		if dlErr != nil {
			return nil, "", fmt.Errorf("failed to download from cloud: %w", dlErr)
		}
		defer reader.Close()
		content, err = io.ReadAll(reader)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read cloud export: %w", err)
		}
	} else {
		// Read from local filesystem
		content, err = os.ReadFile(export.FilePath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read export file: %w", err)
		}
	}

	// Verify checksum
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])
	if checksum != export.FileChecksum {
		return nil, "", fmt.Errorf("export file checksum mismatch")
	}

	filename := filepath.Base(export.FilePath)
	return content, filename, nil
}

// GetExportDownloadURL returns a presigned URL for a cloud export.
// Returns empty string if the export is local or no storage backend is configured.
func (s *AuditExportService) GetExportDownloadURL(ctx context.Context, orgID, id string) (string, error) {
	export, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return "", err
	}

	if export.Status != AuditExportStatusCompleted {
		return "", fmt.Errorf("export not completed, status: %s", export.Status)
	}

	if export.StorageKey == "" || s.storageBackend == nil {
		return "", nil
	}

	url, err := s.storageBackend.GeneratePresignedURL(ctx, export.StorageKey, 1*time.Hour)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}
	return url, nil
}

// ProcessPendingExports processes all pending exports.
func (s *AuditExportService) ProcessPendingExports(ctx context.Context) error {
	exports, err := s.repo.GetPending(ctx)
	if err != nil {
		return fmt.Errorf("failed to get pending exports: %w", err)
	}

	for _, export := range exports {
		if err := s.ProcessExport(ctx, export); err != nil {
			// Log error but continue with other exports
			continue
		}
	}

	return nil
}

// CleanupExpiredExports removes expired exports and their files.
func (s *AuditExportService) CleanupExpiredExports(ctx context.Context) error {
	exports, err := s.repo.GetExpired(ctx)
	if err != nil {
		return fmt.Errorf("failed to get expired exports: %w", err)
	}

	for _, export := range exports {
		// Delete from cloud or local storage
		if export.StorageKey != "" && s.storageBackend != nil {
			if delErr := s.storageBackend.Delete(ctx, export.StorageKey); delErr != nil {
				log.Printf("[RBIAudit] Warning: failed to delete expired cloud object %s: %v", export.StorageKey, delErr)
			}
		} else if export.FilePath != "" && !strings.HasPrefix(export.FilePath, "cloud://") {
			os.Remove(export.FilePath)
		}

		// Update status to expired
		export.Status = AuditExportStatusExpired
		s.repo.Update(ctx, export)
	}

	return nil
}
