// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/rls"
)

// #3103. Migration 301 switches RLS on for all seven rbi_* tables with a
// `FOR ALL USING (org_id = get_current_org_id())` policy, but this package
// never set app.current_org_id — so on an axonflow_app_role pool every read
// here returned SILENT ZERO ROWS and every write was refused. Every statement
// below therefore runs inside rls.WithOrgScope, which opens a transaction and
// SET LOCALs the GUC the policy reads. The hand-written `WHERE org_id = $n`
// predicates are KEPT: the wrap is a backstop, not a replacement.

// ErrBoardReportNotFound is returned when a board report is not found.
var ErrBoardReportNotFound = errors.New("board report not found")

// BoardReportRepository provides data access for board reports.
type BoardReportRepository interface {
	Create(ctx context.Context, report *BoardReport) error
	Get(ctx context.Context, orgID, id string) (*BoardReport, error)
	List(ctx context.Context, orgID string, params *ListBoardReportsParams) ([]*BoardReport, int, error)
	ListByQuarter(ctx context.Context, orgID, quarter string) ([]*BoardReport, error)
	Update(ctx context.Context, report *BoardReport) error
	Delete(ctx context.Context, orgID, id string) error
	GetLatest(ctx context.Context, orgID string, reportType ReportType) (*BoardReport, error)
	GetPendingApproval(ctx context.Context, orgID string) ([]*BoardReport, error)
}

// ListBoardReportsParams defines filtering parameters for listing board reports.
type ListBoardReportsParams struct {
	ReportType     string
	Quarter        string
	ApprovalStatus string
	StartDate      *time.Time
	EndDate        *time.Time
	Limit          int
	Offset         int
}

// PostgresBoardReportRepository implements BoardReportRepository using PostgreSQL.
type PostgresBoardReportRepository struct {
	db *sql.DB
}

// NewPostgresBoardReportRepository creates a new PostgreSQL-backed board report repository.
func NewPostgresBoardReportRepository(db *sql.DB) *PostgresBoardReportRepository {
	return &PostgresBoardReportRepository{db: db}
}

// Create inserts a new board report.
func (r *PostgresBoardReportRepository) Create(ctx context.Context, report *BoardReport) error {
	if report.ID == "" {
		report.ID = uuid.New().String()
	}
	report.CreatedAt = time.Now().UTC()
	report.UpdatedAt = report.CreatedAt

	// Serialize JSON fields
	systemsByRiskJSON, err := json.Marshal(report.SystemsByRisk)
	if err != nil {
		return fmt.Errorf("failed to marshal systems_by_risk: %w", err)
	}
	systemsByStatusJSON, err := json.Marshal(report.SystemsByStatus)
	if err != nil {
		return fmt.Errorf("failed to marshal systems_by_status: %w", err)
	}
	validationsByTypeJSON, err := json.Marshal(report.ValidationsByType)
	if err != nil {
		return fmt.Errorf("failed to marshal validations_by_type: %w", err)
	}
	validationsByRecommendationJSON, err := json.Marshal(report.ValidationsByRecommendation)
	if err != nil {
		return fmt.Errorf("failed to marshal validations_by_recommendation: %w", err)
	}
	incidentsBySeverityJSON, err := json.Marshal(report.IncidentsBySeverity)
	if err != nil {
		return fmt.Errorf("failed to marshal incidents_by_severity: %w", err)
	}
	incidentsByTypeJSON, err := json.Marshal(report.IncidentsByType)
	if err != nil {
		return fmt.Errorf("failed to marshal incidents_by_type: %w", err)
	}
	keyMetricsJSON, err := json.Marshal(report.KeyMetrics)
	if err != nil {
		return fmt.Errorf("failed to marshal key_metrics: %w", err)
	}
	complianceIssuesJSON, err := json.Marshal(report.ComplianceIssues)
	if err != nil {
		return fmt.Errorf("failed to marshal compliance_issues: %w", err)
	}
	correctiveActionsJSON, err := json.Marshal(report.CorrectiveActions)
	if err != nil {
		return fmt.Errorf("failed to marshal corrective_actions: %w", err)
	}
	killSwitchDetailsJSON, err := json.Marshal(report.KillSwitchDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal kill_switch_details: %w", err)
	}

	query := `
		INSERT INTO rbi_board_reports (
			id, org_id, report_type, report_period_start, report_period_end, report_quarter,
			total_ai_systems, systems_by_risk, systems_by_status, new_systems_deployed, systems_deprecated,
			total_validations, validations_by_type, validations_by_recommendation, overdue_validations,
			total_incidents, incidents_by_severity, incidents_by_type, incidents_resolved, incidents_open,
			average_resolution_time_hours, key_metrics, compliance_score, compliance_issues,
			corrective_actions, kill_switch_activations, kill_switch_details,
			generated_by, generated_by_email, generated_at, generation_method,
			approval_status, approved_by, approved_by_email, approved_at, approval_notes,
			file_path, file_format, file_size_bytes, file_checksum,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40,
			$41, $42
		)
	`

	err = rls.WithOrgScope(ctx, r.db, report.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			report.ID,
			report.OrgID,
			string(report.ReportType),
			nullTime(report.ReportPeriodStart),
			nullTime(report.ReportPeriodEnd),
			nullString(report.ReportQuarter),
			report.TotalAISystems,
			systemsByRiskJSON,
			systemsByStatusJSON,
			report.NewSystemsDeployed,
			report.SystemsDeprecated,
			report.TotalValidations,
			validationsByTypeJSON,
			validationsByRecommendationJSON,
			report.OverdueValidations,
			report.TotalIncidents,
			incidentsBySeverityJSON,
			incidentsByTypeJSON,
			report.IncidentsResolved,
			report.IncidentsOpen,
			report.AverageResolutionTimeHours,
			keyMetricsJSON,
			report.ComplianceScore,
			complianceIssuesJSON,
			correctiveActionsJSON,
			report.KillSwitchActivations,
			killSwitchDetailsJSON,
			nullString(report.GeneratedBy),
			nullString(report.GeneratedByEmail),
			report.GeneratedAt,
			nullString(report.GenerationMethod),
			string(report.ApprovalStatus),
			nullString(report.ApprovedBy),
			nullString(report.ApprovedByEmail),
			nullTime(report.ApprovedAt),
			nullString(report.ApprovalNotes),
			nullString(report.FilePath),
			nullString(report.FileFormat),
			report.FileSizeBytes,
			nullString(report.FileChecksum),
			report.CreatedAt,
			report.UpdatedAt,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to create board report: %w", err)
	}

	return nil
}

// Get retrieves a board report by ID.
func (r *PostgresBoardReportRepository) Get(ctx context.Context, orgID, id string) (*BoardReport, error) {
	query := `
		SELECT
			id, org_id, report_type, report_period_start, report_period_end, report_quarter,
			total_ai_systems, systems_by_risk, systems_by_status, new_systems_deployed, systems_deprecated,
			total_validations, validations_by_type, validations_by_recommendation, overdue_validations,
			total_incidents, incidents_by_severity, incidents_by_type, incidents_resolved, incidents_open,
			average_resolution_time_hours, key_metrics, compliance_score, compliance_issues,
			corrective_actions, kill_switch_activations, kill_switch_details,
			generated_by, generated_by_email, generated_at, generation_method,
			approval_status, approved_by, approved_by_email, approved_at, approval_notes,
			file_path, file_format, file_size_bytes, file_checksum,
			created_at, updated_at
		FROM rbi_board_reports
		WHERE id = $1 AND org_id = $2
	`
	var report *BoardReport
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var scanErr error
		report, scanErr = r.scanBoardReport(tx.QueryRowContext(ctx, query, id, orgID))
		return scanErr
	}); err != nil {
		return nil, err
	}
	return report, nil
}

// List retrieves board reports with optional filtering.
func (r *PostgresBoardReportRepository) List(ctx context.Context, orgID string, params *ListBoardReportsParams) ([]*BoardReport, int, error) {
	if params == nil {
		params = &ListBoardReportsParams{}
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 100 {
		params.Limit = 100
	}

	// Build WHERE clause
	conditions := []string{"org_id = $1"}
	args := []interface{}{orgID}
	argIdx := 2

	if params.ReportType != "" {
		conditions = append(conditions, fmt.Sprintf("report_type = $%d", argIdx))
		args = append(args, params.ReportType)
		argIdx++
	}
	if params.Quarter != "" {
		conditions = append(conditions, fmt.Sprintf("report_quarter = $%d", argIdx))
		args = append(args, params.Quarter)
		argIdx++
	}
	if params.ApprovalStatus != "" {
		conditions = append(conditions, fmt.Sprintf("approval_status = $%d", argIdx))
		args = append(args, params.ApprovalStatus)
		argIdx++
	}
	if params.StartDate != nil {
		conditions = append(conditions, fmt.Sprintf("generated_at >= $%d", argIdx))
		args = append(args, *params.StartDate)
		argIdx++
	}
	if params.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("generated_at <= $%d", argIdx))
		args = append(args, *params.EndDate)
		argIdx++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM rbi_board_reports WHERE %s", whereClause)

	// Fetch records
	query := fmt.Sprintf(`
		SELECT
			id, org_id, report_type, report_period_start, report_period_end, report_quarter,
			total_ai_systems, systems_by_risk, systems_by_status, new_systems_deployed, systems_deprecated,
			total_validations, validations_by_type, validations_by_recommendation, overdue_validations,
			total_incidents, incidents_by_severity, incidents_by_type, incidents_resolved, incidents_open,
			average_resolution_time_hours, key_metrics, compliance_score, compliance_issues,
			corrective_actions, kill_switch_activations, kill_switch_details,
			generated_by, generated_by_email, generated_at, generation_method,
			approval_status, approved_by, approved_by_email, approved_at, approval_notes,
			file_path, file_format, file_size_bytes, file_checksum,
			created_at, updated_at
		FROM rbi_board_reports
		WHERE %s
		ORDER BY generated_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)
	countArgs := args
	args = append(append([]interface{}{}, args...), params.Limit, params.Offset)

	// One wrap for BOTH statements: the count and the page are separate call
	// sites and each had to be scoped, and sharing the transaction also makes
	// total and rows a consistent snapshot.
	var reports []*BoardReport
	var total int
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return fmt.Errorf("failed to count board reports: %w", err)
		}

		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to list board reports: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			report, scanErr := r.scanBoardReportRows(rows)
			if scanErr != nil {
				return scanErr
			}
			reports = append(reports, report)
		}

		return rows.Err()
	}); err != nil {
		return nil, 0, err
	}

	return reports, total, nil
}

// ListByQuarter retrieves board reports for a specific quarter.
func (r *PostgresBoardReportRepository) ListByQuarter(ctx context.Context, orgID, quarter string) ([]*BoardReport, error) {
	query := `
		SELECT
			id, org_id, report_type, report_period_start, report_period_end, report_quarter,
			total_ai_systems, systems_by_risk, systems_by_status, new_systems_deployed, systems_deprecated,
			total_validations, validations_by_type, validations_by_recommendation, overdue_validations,
			total_incidents, incidents_by_severity, incidents_by_type, incidents_resolved, incidents_open,
			average_resolution_time_hours, key_metrics, compliance_score, compliance_issues,
			corrective_actions, kill_switch_activations, kill_switch_details,
			generated_by, generated_by_email, generated_at, generation_method,
			approval_status, approved_by, approved_by_email, approved_at, approval_notes,
			file_path, file_format, file_size_bytes, file_checksum,
			created_at, updated_at
		FROM rbi_board_reports
		WHERE org_id = $1 AND report_quarter = $2
		ORDER BY generated_at DESC
	`

	var reports []*BoardReport
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID, quarter)
		if err != nil {
			return fmt.Errorf("failed to list board reports by quarter: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			report, scanErr := r.scanBoardReportRows(rows)
			if scanErr != nil {
				return scanErr
			}
			reports = append(reports, report)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return reports, nil
}

// Update updates an existing board report.
func (r *PostgresBoardReportRepository) Update(ctx context.Context, report *BoardReport) error {
	report.UpdatedAt = time.Now().UTC()

	// Serialize JSON fields
	systemsByRiskJSON, _ := json.Marshal(report.SystemsByRisk)
	systemsByStatusJSON, _ := json.Marshal(report.SystemsByStatus)
	validationsByTypeJSON, _ := json.Marshal(report.ValidationsByType)
	validationsByRecommendationJSON, _ := json.Marshal(report.ValidationsByRecommendation)
	incidentsBySeverityJSON, _ := json.Marshal(report.IncidentsBySeverity)
	incidentsByTypeJSON, _ := json.Marshal(report.IncidentsByType)
	keyMetricsJSON, _ := json.Marshal(report.KeyMetrics)
	complianceIssuesJSON, _ := json.Marshal(report.ComplianceIssues)
	correctiveActionsJSON, _ := json.Marshal(report.CorrectiveActions)
	killSwitchDetailsJSON, _ := json.Marshal(report.KillSwitchDetails)

	query := `
		UPDATE rbi_board_reports SET
			report_type = $3, report_period_start = $4, report_period_end = $5, report_quarter = $6,
			total_ai_systems = $7, systems_by_risk = $8, systems_by_status = $9,
			new_systems_deployed = $10, systems_deprecated = $11,
			total_validations = $12, validations_by_type = $13, validations_by_recommendation = $14,
			overdue_validations = $15, total_incidents = $16, incidents_by_severity = $17,
			incidents_by_type = $18, incidents_resolved = $19, incidents_open = $20,
			average_resolution_time_hours = $21, key_metrics = $22, compliance_score = $23,
			compliance_issues = $24, corrective_actions = $25, kill_switch_activations = $26,
			kill_switch_details = $27, approval_status = $28, approved_by = $29,
			approved_by_email = $30, approved_at = $31, approval_notes = $32,
			file_path = $33, file_format = $34, file_size_bytes = $35, file_checksum = $36,
			updated_at = $37
		WHERE id = $1 AND org_id = $2
	`

	var result sql.Result
	err := rls.WithOrgScope(ctx, r.db, report.OrgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx, query,
			report.ID,
			report.OrgID,
			string(report.ReportType),
			nullTime(report.ReportPeriodStart),
			nullTime(report.ReportPeriodEnd),
			nullString(report.ReportQuarter),
			report.TotalAISystems,
			systemsByRiskJSON,
			systemsByStatusJSON,
			report.NewSystemsDeployed,
			report.SystemsDeprecated,
			report.TotalValidations,
			validationsByTypeJSON,
			validationsByRecommendationJSON,
			report.OverdueValidations,
			report.TotalIncidents,
			incidentsBySeverityJSON,
			incidentsByTypeJSON,
			report.IncidentsResolved,
			report.IncidentsOpen,
			report.AverageResolutionTimeHours,
			keyMetricsJSON,
			report.ComplianceScore,
			complianceIssuesJSON,
			correctiveActionsJSON,
			report.KillSwitchActivations,
			killSwitchDetailsJSON,
			string(report.ApprovalStatus),
			nullString(report.ApprovedBy),
			nullString(report.ApprovedByEmail),
			nullTime(report.ApprovedAt),
			nullString(report.ApprovalNotes),
			nullString(report.FilePath),
			nullString(report.FileFormat),
			report.FileSizeBytes,
			nullString(report.FileChecksum),
			report.UpdatedAt,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to update board report: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrBoardReportNotFound
	}

	return nil
}

// Delete removes a board report.
func (r *PostgresBoardReportRepository) Delete(ctx context.Context, orgID, id string) error {
	var result sql.Result
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx,
			"DELETE FROM rbi_board_reports WHERE id = $1 AND org_id = $2",
			id, orgID,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to delete board report: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrBoardReportNotFound
	}

	return nil
}

// GetLatest retrieves the most recent board report of a given type.
func (r *PostgresBoardReportRepository) GetLatest(ctx context.Context, orgID string, reportType ReportType) (*BoardReport, error) {
	query := `
		SELECT
			id, org_id, report_type, report_period_start, report_period_end, report_quarter,
			total_ai_systems, systems_by_risk, systems_by_status, new_systems_deployed, systems_deprecated,
			total_validations, validations_by_type, validations_by_recommendation, overdue_validations,
			total_incidents, incidents_by_severity, incidents_by_type, incidents_resolved, incidents_open,
			average_resolution_time_hours, key_metrics, compliance_score, compliance_issues,
			corrective_actions, kill_switch_activations, kill_switch_details,
			generated_by, generated_by_email, generated_at, generation_method,
			approval_status, approved_by, approved_by_email, approved_at, approval_notes,
			file_path, file_format, file_size_bytes, file_checksum,
			created_at, updated_at
		FROM rbi_board_reports
		WHERE org_id = $1 AND report_type = $2
		ORDER BY generated_at DESC
		LIMIT 1
	`
	var report *BoardReport
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var scanErr error
		report, scanErr = r.scanBoardReport(tx.QueryRowContext(ctx, query, orgID, string(reportType)))
		return scanErr
	}); err != nil {
		return nil, err
	}
	return report, nil
}

// GetPendingApproval retrieves board reports pending approval.
func (r *PostgresBoardReportRepository) GetPendingApproval(ctx context.Context, orgID string) ([]*BoardReport, error) {
	query := `
		SELECT
			id, org_id, report_type, report_period_start, report_period_end, report_quarter,
			total_ai_systems, systems_by_risk, systems_by_status, new_systems_deployed, systems_deprecated,
			total_validations, validations_by_type, validations_by_recommendation, overdue_validations,
			total_incidents, incidents_by_severity, incidents_by_type, incidents_resolved, incidents_open,
			average_resolution_time_hours, key_metrics, compliance_score, compliance_issues,
			corrective_actions, kill_switch_activations, kill_switch_details,
			generated_by, generated_by_email, generated_at, generation_method,
			approval_status, approved_by, approved_by_email, approved_at, approval_notes,
			file_path, file_format, file_size_bytes, file_checksum,
			created_at, updated_at
		FROM rbi_board_reports
		WHERE org_id = $1 AND approval_status = 'pending_review'
		ORDER BY generated_at DESC
	`

	var reports []*BoardReport
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID)
		if err != nil {
			return fmt.Errorf("failed to get pending approval reports: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			report, scanErr := r.scanBoardReportRows(rows)
			if scanErr != nil {
				return scanErr
			}
			reports = append(reports, report)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return reports, nil
}

// scanBoardReport scans a single row into a BoardReport.
func (r *PostgresBoardReportRepository) scanBoardReport(row *sql.Row) (*BoardReport, error) {
	var report BoardReport
	var reportPeriodStart, reportPeriodEnd, approvedAt sql.NullTime
	var reportQuarter, generatedBy, generatedByEmail, generationMethod sql.NullString
	var approvedBy, approvedByEmail, approvalNotes sql.NullString
	var filePath, fileFormat, fileChecksum sql.NullString
	// #3246: every counter below is a NULLABLE column in
	// migrations/industry/banking/301 (`total_ai_systems INTEGER`, no NOT NULL,
	// no DEFAULT). Scanning a NULL into a plain int fails the whole row with
	// `converting NULL to int is unsupported`, so ONE board report written by a
	// generator that left a counter unset 500s the entire list endpoint.
	var counters boardReportCounters
	var systemsByRiskJSON, systemsByStatusJSON []byte
	var validationsByTypeJSON, validationsByRecommendationJSON []byte
	var incidentsBySeverityJSON, incidentsByTypeJSON []byte
	var keyMetricsJSON, complianceIssuesJSON, correctiveActionsJSON []byte
	var killSwitchDetailsJSON []byte

	err := row.Scan(
		&report.ID, &report.OrgID, &report.ReportType,
		&reportPeriodStart, &reportPeriodEnd, &reportQuarter,
		&counters.TotalAISystems, &systemsByRiskJSON, &systemsByStatusJSON,
		&counters.NewSystemsDeployed, &counters.SystemsDeprecated,
		&counters.TotalValidations, &validationsByTypeJSON, &validationsByRecommendationJSON,
		&counters.OverdueValidations,
		&counters.TotalIncidents, &incidentsBySeverityJSON, &incidentsByTypeJSON,
		&counters.IncidentsResolved, &counters.IncidentsOpen,
		&counters.AverageResolutionTimeHours, &keyMetricsJSON, &counters.ComplianceScore,
		&complianceIssuesJSON, &correctiveActionsJSON, &counters.KillSwitchActivations,
		&killSwitchDetailsJSON,
		&generatedBy, &generatedByEmail, &counters.GeneratedAt, &generationMethod,
		&counters.ApprovalStatus, &approvedBy, &approvedByEmail, &approvedAt, &approvalNotes,
		&filePath, &fileFormat, &counters.FileSizeBytes, &fileChecksum,
		&counters.CreatedAt, &counters.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrBoardReportNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan board report: %w", err)
	}
	counters.applyTo(&report)

	// Handle nullable fields
	if reportPeriodStart.Valid {
		report.ReportPeriodStart = &reportPeriodStart.Time
	}
	if reportPeriodEnd.Valid {
		report.ReportPeriodEnd = &reportPeriodEnd.Time
	}
	if reportQuarter.Valid {
		report.ReportQuarter = reportQuarter.String
	}
	if generatedBy.Valid {
		report.GeneratedBy = generatedBy.String
	}
	if generatedByEmail.Valid {
		report.GeneratedByEmail = generatedByEmail.String
	}
	if generationMethod.Valid {
		report.GenerationMethod = generationMethod.String
	}
	if approvedBy.Valid {
		report.ApprovedBy = approvedBy.String
	}
	if approvedByEmail.Valid {
		report.ApprovedByEmail = approvedByEmail.String
	}
	if approvedAt.Valid {
		report.ApprovedAt = &approvedAt.Time
	}
	if approvalNotes.Valid {
		report.ApprovalNotes = approvalNotes.String
	}
	if filePath.Valid {
		report.FilePath = filePath.String
	}
	if fileFormat.Valid {
		report.FileFormat = fileFormat.String
	}
	if fileChecksum.Valid {
		report.FileChecksum = fileChecksum.String
	}

	// Unmarshal JSON
	if len(systemsByRiskJSON) > 0 {
		json.Unmarshal(systemsByRiskJSON, &report.SystemsByRisk)
	}
	if len(systemsByStatusJSON) > 0 {
		json.Unmarshal(systemsByStatusJSON, &report.SystemsByStatus)
	}
	if len(validationsByTypeJSON) > 0 {
		json.Unmarshal(validationsByTypeJSON, &report.ValidationsByType)
	}
	if len(validationsByRecommendationJSON) > 0 {
		json.Unmarshal(validationsByRecommendationJSON, &report.ValidationsByRecommendation)
	}
	if len(incidentsBySeverityJSON) > 0 {
		json.Unmarshal(incidentsBySeverityJSON, &report.IncidentsBySeverity)
	}
	if len(incidentsByTypeJSON) > 0 {
		json.Unmarshal(incidentsByTypeJSON, &report.IncidentsByType)
	}
	if len(keyMetricsJSON) > 0 {
		json.Unmarshal(keyMetricsJSON, &report.KeyMetrics)
	}
	if len(complianceIssuesJSON) > 0 {
		json.Unmarshal(complianceIssuesJSON, &report.ComplianceIssues)
	}
	if len(correctiveActionsJSON) > 0 {
		json.Unmarshal(correctiveActionsJSON, &report.CorrectiveActions)
	}
	if len(killSwitchDetailsJSON) > 0 {
		json.Unmarshal(killSwitchDetailsJSON, &report.KillSwitchDetails)
	}

	return &report, nil
}

// scanBoardReportRows scans a row from rows into a BoardReport.
func (r *PostgresBoardReportRepository) scanBoardReportRows(rows *sql.Rows) (*BoardReport, error) {
	var report BoardReport
	var reportPeriodStart, reportPeriodEnd, approvedAt sql.NullTime
	var reportQuarter, generatedBy, generatedByEmail, generationMethod sql.NullString
	var approvedBy, approvedByEmail, approvalNotes sql.NullString
	var filePath, fileFormat, fileChecksum sql.NullString
	// #3246: every counter below is a NULLABLE column in
	// migrations/industry/banking/301 (`total_ai_systems INTEGER`, no NOT NULL,
	// no DEFAULT). Scanning a NULL into a plain int fails the whole row with
	// `converting NULL to int is unsupported`, so ONE board report written by a
	// generator that left a counter unset 500s the entire list endpoint.
	var counters boardReportCounters
	var systemsByRiskJSON, systemsByStatusJSON []byte
	var validationsByTypeJSON, validationsByRecommendationJSON []byte
	var incidentsBySeverityJSON, incidentsByTypeJSON []byte
	var keyMetricsJSON, complianceIssuesJSON, correctiveActionsJSON []byte
	var killSwitchDetailsJSON []byte

	err := rows.Scan(
		&report.ID, &report.OrgID, &report.ReportType,
		&reportPeriodStart, &reportPeriodEnd, &reportQuarter,
		&counters.TotalAISystems, &systemsByRiskJSON, &systemsByStatusJSON,
		&counters.NewSystemsDeployed, &counters.SystemsDeprecated,
		&counters.TotalValidations, &validationsByTypeJSON, &validationsByRecommendationJSON,
		&counters.OverdueValidations,
		&counters.TotalIncidents, &incidentsBySeverityJSON, &incidentsByTypeJSON,
		&counters.IncidentsResolved, &counters.IncidentsOpen,
		&counters.AverageResolutionTimeHours, &keyMetricsJSON, &counters.ComplianceScore,
		&complianceIssuesJSON, &correctiveActionsJSON, &counters.KillSwitchActivations,
		&killSwitchDetailsJSON,
		&generatedBy, &generatedByEmail, &counters.GeneratedAt, &generationMethod,
		&counters.ApprovalStatus, &approvedBy, &approvedByEmail, &approvedAt, &approvalNotes,
		&filePath, &fileFormat, &counters.FileSizeBytes, &fileChecksum,
		&counters.CreatedAt, &counters.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan board report row: %w", err)
	}
	counters.applyTo(&report)

	// Handle nullable fields (same as scanBoardReport)
	if reportPeriodStart.Valid {
		report.ReportPeriodStart = &reportPeriodStart.Time
	}
	if reportPeriodEnd.Valid {
		report.ReportPeriodEnd = &reportPeriodEnd.Time
	}
	if reportQuarter.Valid {
		report.ReportQuarter = reportQuarter.String
	}
	if generatedBy.Valid {
		report.GeneratedBy = generatedBy.String
	}
	if generatedByEmail.Valid {
		report.GeneratedByEmail = generatedByEmail.String
	}
	if generationMethod.Valid {
		report.GenerationMethod = generationMethod.String
	}
	if approvedBy.Valid {
		report.ApprovedBy = approvedBy.String
	}
	if approvedByEmail.Valid {
		report.ApprovedByEmail = approvedByEmail.String
	}
	if approvedAt.Valid {
		report.ApprovedAt = &approvedAt.Time
	}
	if approvalNotes.Valid {
		report.ApprovalNotes = approvalNotes.String
	}
	if filePath.Valid {
		report.FilePath = filePath.String
	}
	if fileFormat.Valid {
		report.FileFormat = fileFormat.String
	}
	if fileChecksum.Valid {
		report.FileChecksum = fileChecksum.String
	}

	// Unmarshal JSON
	if len(systemsByRiskJSON) > 0 {
		json.Unmarshal(systemsByRiskJSON, &report.SystemsByRisk)
	}
	if len(systemsByStatusJSON) > 0 {
		json.Unmarshal(systemsByStatusJSON, &report.SystemsByStatus)
	}
	if len(validationsByTypeJSON) > 0 {
		json.Unmarshal(validationsByTypeJSON, &report.ValidationsByType)
	}
	if len(validationsByRecommendationJSON) > 0 {
		json.Unmarshal(validationsByRecommendationJSON, &report.ValidationsByRecommendation)
	}
	if len(incidentsBySeverityJSON) > 0 {
		json.Unmarshal(incidentsBySeverityJSON, &report.IncidentsBySeverity)
	}
	if len(incidentsByTypeJSON) > 0 {
		json.Unmarshal(incidentsByTypeJSON, &report.IncidentsByType)
	}
	if len(keyMetricsJSON) > 0 {
		json.Unmarshal(keyMetricsJSON, &report.KeyMetrics)
	}
	if len(complianceIssuesJSON) > 0 {
		json.Unmarshal(complianceIssuesJSON, &report.ComplianceIssues)
	}
	if len(correctiveActionsJSON) > 0 {
		json.Unmarshal(correctiveActionsJSON, &report.CorrectiveActions)
	}
	if len(killSwitchDetailsJSON) > 0 {
		json.Unmarshal(killSwitchDetailsJSON, &report.KillSwitchDetails)
	}

	return &report, nil
}

// boardReportCounters holds the NULLABLE numeric columns of rbi_board_reports
// so both scan paths read them the same way (#3246).
//
// THE DEFECT
//
//	migrations/industry/banking/301 declares every one of these without NOT NULL
//	and (except kill_switch_activations) without a DEFAULT:
//
//	  total_ai_systems INTEGER,
//	  average_resolution_time_hours DECIMAL(10, 2),
//	  compliance_score DECIMAL(5, 2),
//	  ...
//
//	They were scanned straight into `int` / `float64` / `int64` fields. A single
//	board report whose generator left one counter unset makes database/sql
//	return `converting NULL to int is unsupported`, and because the list handler
//	returns on the first scan error, ONE such row 500s the whole list for the
//	organization - not just that report.
//
// WHY A STRUCT RATHER THAN TWELVE LOCALS IN EACH FUNCTION
//
//	scanBoardReport and scanBoardReportRows are near-duplicates that already
//	drifted once. Twelve sql.Null* locals plus twelve Valid checks, written out
//	twice, is twenty-four opportunities for the two paths to disagree about what
//	a NULL counter means. One type, one applyTo, both callers.
//
// A NULL counter becomes the ZERO VALUE, which is the honest reading: the
// column is "how many of X were there", and a report that never recorded a
// count has no basis for claiming any other number. It is also what every
// consumer already assumed, since before this the row simply failed.
type boardReportCounters struct {
	TotalAISystems             sql.NullInt64
	NewSystemsDeployed         sql.NullInt64
	SystemsDeprecated          sql.NullInt64
	TotalValidations           sql.NullInt64
	OverdueValidations         sql.NullInt64
	TotalIncidents             sql.NullInt64
	IncidentsResolved          sql.NullInt64
	IncidentsOpen              sql.NullInt64
	AverageResolutionTimeHours sql.NullFloat64
	ComplianceScore            sql.NullFloat64
	KillSwitchActivations      sql.NullInt64
	FileSizeBytes              sql.NullInt64
	// #3241 round 2 (R3): these four are nullable in migration 301 too -
	// `generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()`, `approval_status
	// VARCHAR(20) DEFAULT 'draft'`, and both audit timestamps. A DEFAULT does
	// not stop an explicit NULL, and the first pass at this fix covered the 12
	// numeric columns and left these, on exactly the premise it had just
	// rejected for the others.
	GeneratedAt    sql.NullTime
	ApprovalStatus sql.NullString
	CreatedAt      sql.NullTime
	UpdatedAt      sql.NullTime
}

// applyTo copies the scanned counters onto the report, mapping NULL to zero.
func (c boardReportCounters) applyTo(report *BoardReport) {
	report.TotalAISystems = int(c.TotalAISystems.Int64)
	report.NewSystemsDeployed = int(c.NewSystemsDeployed.Int64)
	report.SystemsDeprecated = int(c.SystemsDeprecated.Int64)
	report.TotalValidations = int(c.TotalValidations.Int64)
	report.OverdueValidations = int(c.OverdueValidations.Int64)
	report.TotalIncidents = int(c.TotalIncidents.Int64)
	report.IncidentsResolved = int(c.IncidentsResolved.Int64)
	report.IncidentsOpen = int(c.IncidentsOpen.Int64)
	report.AverageResolutionTimeHours = c.AverageResolutionTimeHours.Float64
	report.ComplianceScore = c.ComplianceScore.Float64
	report.KillSwitchActivations = int(c.KillSwitchActivations.Int64)
	report.FileSizeBytes = c.FileSizeBytes.Int64
	report.GeneratedAt = c.GeneratedAt.Time
	// NULL -> the column's own DEFAULT ('draft'), not "".
	//
	// "" is not a member of ReportApprovalStatus and fails its Valid(), and it
	// would turn a guard into a fail-open: boardreport_service.go DeleteReport
	// refuses only when ApprovalStatus == ReportApprovalApproved, so an empty
	// value sails past it. Before the nullable-scan fix that row made Get
	// ERROR, so nothing was deleted - mapping NULL to "" would have converted a
	// loud failure into a silent successful delete of a report whose approval
	// state is unknown.
	//
	// 'draft' is the honest reading as well as the safe one: it is what the
	// column defaults to, so a row with no recorded status is a row that was
	// never advanced past draft.
	report.ApprovalStatus = ReportApprovalDraft
	if c.ApprovalStatus.Valid && c.ApprovalStatus.String != "" {
		report.ApprovalStatus = ReportApprovalStatus(c.ApprovalStatus.String)
	}
	report.CreatedAt = c.CreatedAt.Time
	report.UpdatedAt = c.UpdatedAt.Time
}
