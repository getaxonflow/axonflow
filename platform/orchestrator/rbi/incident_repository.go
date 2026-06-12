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
)

// ErrIncidentNotFound is returned when an incident is not found.
var ErrIncidentNotFound = errors.New("incident not found")

// AIIncidentRepository provides data access for AI incidents.
type AIIncidentRepository interface {
	Create(ctx context.Context, incident *AIIncident) error
	Get(ctx context.Context, orgID, id string) (*AIIncident, error)
	GetByIncidentID(ctx context.Context, orgID, incidentID string) (*AIIncident, error)
	List(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error)
	ListBySystem(ctx context.Context, orgID, systemID string) ([]*AIIncident, error)
	Update(ctx context.Context, incident *AIIncident) error
	Delete(ctx context.Context, orgID, id string) error
	GetOpenIncidents(ctx context.Context, orgID string) ([]*AIIncident, error)
	GetPendingNotifications(ctx context.Context, orgID string, notificationType string) ([]*AIIncident, error)
}

// ListIncidentsParams defines filtering parameters for listing incidents.
type ListIncidentsParams struct {
	SystemID      string
	IncidentType  string
	Severity      string
	Status        string
	StartDate     *time.Time
	EndDate       *time.Time
	BoardNotified *bool
	RBINotified   *bool
	Limit         int
	Offset        int
}

// PostgresAIIncidentRepository implements AIIncidentRepository using PostgreSQL.
type PostgresAIIncidentRepository struct {
	db *sql.DB
}

// NewPostgresAIIncidentRepository creates a new PostgreSQL-backed incident repository.
func NewPostgresAIIncidentRepository(db *sql.DB) *PostgresAIIncidentRepository {
	return &PostgresAIIncidentRepository{db: db}
}

// Create inserts a new AI incident.
func (r *PostgresAIIncidentRepository) Create(ctx context.Context, incident *AIIncident) error {
	if incident.ID == "" {
		incident.ID = uuid.New().String()
	}
	if incident.IncidentID == "" {
		incident.IncidentID = fmt.Sprintf("INC-%s", uuid.New().String()[:8])
	}
	incident.CreatedAt = time.Now().UTC()
	incident.UpdatedAt = incident.CreatedAt

	// Serialize JSON fields
	remediationActionsJSON, err := json.Marshal(incident.RemediationActions)
	if err != nil {
		return fmt.Errorf("failed to marshal remediation_actions: %w", err)
	}
	evidenceFilesJSON, err := json.Marshal(incident.EvidenceFiles)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence_files: %w", err)
	}
	tagsJSON, err := json.Marshal(incident.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}
	metadataJSON, err := json.Marshal(incident.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// board_notification_required and rbi_notification_required are
	// GENERATED ALWAYS AS (...) STORED columns (migration 301): Postgres
	// computes them from severity / incident_type and REJECTS any attempt to
	// write them ("cannot insert a non-DEFAULT value into column ..."). They
	// are intentionally omitted from this INSERT and read back via scan.
	query := `
		INSERT INTO rbi_ai_incidents (
			id, org_id, incident_id, system_id,
			incident_type, severity,
			detected_at, detected_by, detection_details,
			title, description, root_cause,
			affected_customers_count, affected_transactions_count,
			financial_impact_inr, reputational_impact,
			remediation_actions, immediate_action_taken, long_term_fix,
			status, resolved_at, resolution_summary, lessons_learned,
			board_notified,
			board_notification_date, board_notification_reference,
			rbi_notified,
			rbi_notification_date, rbi_notification_reference, rbi_response,
			evidence_files, tags, metadata,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
			$31, $32, $33, $34, $35
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		incident.ID,
		incident.OrgID,
		incident.IncidentID,
		nullString(incident.SystemID),
		string(incident.IncidentType),
		string(incident.Severity),
		incident.DetectedAt,
		string(incident.DetectedBy),
		nullString(incident.DetectionDetails),
		incident.Title,
		incident.Description,
		nullString(incident.RootCause),
		nullInt(incident.AffectedCustomersCount),
		nullInt(incident.AffectedTransactionsCount),
		nullFloat64(incident.FinancialImpactINR),
		nullString(incident.ReputationalImpact),
		remediationActionsJSON,
		nullString(incident.ImmediateActionTaken),
		nullString(incident.LongTermFix),
		string(incident.Status),
		nullTime(incident.ResolvedAt),
		nullString(incident.ResolutionSummary),
		nullString(incident.LessonsLearned),
		incident.BoardNotified,
		nullTime(incident.BoardNotificationDate),
		nullString(incident.BoardNotificationReference),
		incident.RBINotified,
		nullTime(incident.RBINotificationDate),
		nullString(incident.RBINotificationReference),
		nullString(incident.RBIResponse),
		evidenceFilesJSON,
		tagsJSON,
		metadataJSON,
		incident.CreatedAt,
		incident.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create incident: %w", err)
	}

	return nil
}

// Get retrieves an incident by ID.
func (r *PostgresAIIncidentRepository) Get(ctx context.Context, orgID, id string) (*AIIncident, error) {
	query := `
		SELECT
			id, org_id, incident_id, system_id,
			incident_type, severity,
			detected_at, detected_by, detection_details,
			title, description, root_cause,
			affected_customers_count, affected_transactions_count,
			financial_impact_inr, reputational_impact,
			remediation_actions, immediate_action_taken, long_term_fix,
			status, resolved_at, resolution_summary, lessons_learned,
			board_notification_required, board_notified,
			board_notification_date, board_notification_reference,
			rbi_notification_required, rbi_notified,
			rbi_notification_date, rbi_notification_reference, rbi_response,
			evidence_files, tags, metadata,
			created_at, updated_at
		FROM rbi_ai_incidents
		WHERE id = $1 AND org_id = $2
	`
	return r.scanIncident(r.db.QueryRowContext(ctx, query, id, orgID))
}

// GetByIncidentID retrieves an incident by its incident ID.
func (r *PostgresAIIncidentRepository) GetByIncidentID(ctx context.Context, orgID, incidentID string) (*AIIncident, error) {
	query := `
		SELECT
			id, org_id, incident_id, system_id,
			incident_type, severity,
			detected_at, detected_by, detection_details,
			title, description, root_cause,
			affected_customers_count, affected_transactions_count,
			financial_impact_inr, reputational_impact,
			remediation_actions, immediate_action_taken, long_term_fix,
			status, resolved_at, resolution_summary, lessons_learned,
			board_notification_required, board_notified,
			board_notification_date, board_notification_reference,
			rbi_notification_required, rbi_notified,
			rbi_notification_date, rbi_notification_reference, rbi_response,
			evidence_files, tags, metadata,
			created_at, updated_at
		FROM rbi_ai_incidents
		WHERE incident_id = $1 AND org_id = $2
	`
	return r.scanIncident(r.db.QueryRowContext(ctx, query, incidentID, orgID))
}

// List retrieves incidents with optional filtering.
func (r *PostgresAIIncidentRepository) List(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error) {
	if params == nil {
		params = &ListIncidentsParams{}
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

	if params.SystemID != "" {
		conditions = append(conditions, fmt.Sprintf("system_id = $%d", argIdx))
		args = append(args, params.SystemID)
		argIdx++
	}
	if params.IncidentType != "" {
		conditions = append(conditions, fmt.Sprintf("incident_type = $%d", argIdx))
		args = append(args, params.IncidentType)
		argIdx++
	}
	if params.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, params.Severity)
		argIdx++
	}
	if params.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, params.Status)
		argIdx++
	}
	if params.StartDate != nil {
		conditions = append(conditions, fmt.Sprintf("detected_at >= $%d", argIdx))
		args = append(args, *params.StartDate)
		argIdx++
	}
	if params.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("detected_at <= $%d", argIdx))
		args = append(args, *params.EndDate)
		argIdx++
	}
	if params.BoardNotified != nil {
		conditions = append(conditions, fmt.Sprintf("board_notified = $%d", argIdx))
		args = append(args, *params.BoardNotified)
		argIdx++
	}
	if params.RBINotified != nil {
		conditions = append(conditions, fmt.Sprintf("rbi_notified = $%d", argIdx))
		args = append(args, *params.RBINotified)
		argIdx++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM rbi_ai_incidents WHERE %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count incidents: %w", err)
	}

	// Fetch records
	query := fmt.Sprintf(`
		SELECT
			id, org_id, incident_id, system_id,
			incident_type, severity,
			detected_at, detected_by, detection_details,
			title, description, root_cause,
			affected_customers_count, affected_transactions_count,
			financial_impact_inr, reputational_impact,
			remediation_actions, immediate_action_taken, long_term_fix,
			status, resolved_at, resolution_summary, lessons_learned,
			board_notification_required, board_notified,
			board_notification_date, board_notification_reference,
			rbi_notification_required, rbi_notified,
			rbi_notification_date, rbi_notification_reference, rbi_response,
			evidence_files, tags, metadata,
			created_at, updated_at
		FROM rbi_ai_incidents
		WHERE %s
		ORDER BY detected_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)
	args = append(args, params.Limit, params.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list incidents: %w", err)
	}
	defer rows.Close()

	var incidents []*AIIncident
	for rows.Next() {
		incident, err := r.scanIncidentRows(rows)
		if err != nil {
			return nil, 0, err
		}
		incidents = append(incidents, incident)
	}

	return incidents, total, rows.Err()
}

// ListBySystem retrieves all incidents for a specific system.
func (r *PostgresAIIncidentRepository) ListBySystem(ctx context.Context, orgID, systemID string) ([]*AIIncident, error) {
	query := `
		SELECT
			id, org_id, incident_id, system_id,
			incident_type, severity,
			detected_at, detected_by, detection_details,
			title, description, root_cause,
			affected_customers_count, affected_transactions_count,
			financial_impact_inr, reputational_impact,
			remediation_actions, immediate_action_taken, long_term_fix,
			status, resolved_at, resolution_summary, lessons_learned,
			board_notification_required, board_notified,
			board_notification_date, board_notification_reference,
			rbi_notification_required, rbi_notified,
			rbi_notification_date, rbi_notification_reference, rbi_response,
			evidence_files, tags, metadata,
			created_at, updated_at
		FROM rbi_ai_incidents
		WHERE org_id = $1 AND system_id = $2
		ORDER BY detected_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, orgID, systemID)
	if err != nil {
		return nil, fmt.Errorf("failed to list incidents by system: %w", err)
	}
	defer rows.Close()

	var incidents []*AIIncident
	for rows.Next() {
		incident, err := r.scanIncidentRows(rows)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, incident)
	}

	return incidents, rows.Err()
}

// Update updates an existing incident.
func (r *PostgresAIIncidentRepository) Update(ctx context.Context, incident *AIIncident) error {
	incident.UpdatedAt = time.Now().UTC()

	// Serialize JSON fields
	remediationActionsJSON, err := json.Marshal(incident.RemediationActions)
	if err != nil {
		return fmt.Errorf("failed to marshal remediation_actions: %w", err)
	}
	evidenceFilesJSON, err := json.Marshal(incident.EvidenceFiles)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence_files: %w", err)
	}
	tagsJSON, err := json.Marshal(incident.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}
	metadataJSON, err := json.Marshal(incident.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// board_notification_required / rbi_notification_required are GENERATED
	// ALWAYS columns (migration 301) — Postgres recomputes them from
	// severity / incident_type and rejects any direct write. They are
	// omitted from this SET clause; updating severity/incident_type updates
	// them automatically.
	query := `
		UPDATE rbi_ai_incidents SET
			system_id = $3,
			incident_type = $4, severity = $5,
			detected_at = $6, detected_by = $7, detection_details = $8,
			title = $9, description = $10, root_cause = $11,
			affected_customers_count = $12, affected_transactions_count = $13,
			financial_impact_inr = $14, reputational_impact = $15,
			remediation_actions = $16, immediate_action_taken = $17, long_term_fix = $18,
			status = $19, resolved_at = $20, resolution_summary = $21, lessons_learned = $22,
			board_notified = $23,
			board_notification_date = $24, board_notification_reference = $25,
			rbi_notified = $26,
			rbi_notification_date = $27, rbi_notification_reference = $28, rbi_response = $29,
			evidence_files = $30, tags = $31, metadata = $32,
			updated_at = $33
		WHERE id = $1 AND org_id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		incident.ID,
		incident.OrgID,
		nullString(incident.SystemID),
		string(incident.IncidentType),
		string(incident.Severity),
		incident.DetectedAt,
		string(incident.DetectedBy),
		nullString(incident.DetectionDetails),
		incident.Title,
		incident.Description,
		nullString(incident.RootCause),
		nullInt(incident.AffectedCustomersCount),
		nullInt(incident.AffectedTransactionsCount),
		nullFloat64(incident.FinancialImpactINR),
		nullString(incident.ReputationalImpact),
		remediationActionsJSON,
		nullString(incident.ImmediateActionTaken),
		nullString(incident.LongTermFix),
		string(incident.Status),
		nullTime(incident.ResolvedAt),
		nullString(incident.ResolutionSummary),
		nullString(incident.LessonsLearned),
		incident.BoardNotified,
		nullTime(incident.BoardNotificationDate),
		nullString(incident.BoardNotificationReference),
		incident.RBINotified,
		nullTime(incident.RBINotificationDate),
		nullString(incident.RBINotificationReference),
		nullString(incident.RBIResponse),
		evidenceFilesJSON,
		tagsJSON,
		metadataJSON,
		incident.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update incident: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrIncidentNotFound
	}

	return nil
}

// Delete removes an incident.
func (r *PostgresAIIncidentRepository) Delete(ctx context.Context, orgID, id string) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM rbi_ai_incidents WHERE id = $1 AND org_id = $2",
		id, orgID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete incident: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrIncidentNotFound
	}

	return nil
}

// GetOpenIncidents retrieves all open incidents.
func (r *PostgresAIIncidentRepository) GetOpenIncidents(ctx context.Context, orgID string) ([]*AIIncident, error) {
	query := `
		SELECT
			id, org_id, incident_id, system_id,
			incident_type, severity,
			detected_at, detected_by, detection_details,
			title, description, root_cause,
			affected_customers_count, affected_transactions_count,
			financial_impact_inr, reputational_impact,
			remediation_actions, immediate_action_taken, long_term_fix,
			status, resolved_at, resolution_summary, lessons_learned,
			board_notification_required, board_notified,
			board_notification_date, board_notification_reference,
			rbi_notification_required, rbi_notified,
			rbi_notification_date, rbi_notification_reference, rbi_response,
			evidence_files, tags, metadata,
			created_at, updated_at
		FROM rbi_ai_incidents
		WHERE org_id = $1 AND status NOT IN ('resolved', 'closed')
		ORDER BY severity, detected_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get open incidents: %w", err)
	}
	defer rows.Close()

	var incidents []*AIIncident
	for rows.Next() {
		incident, err := r.scanIncidentRows(rows)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, incident)
	}

	return incidents, rows.Err()
}

// GetPendingNotifications retrieves incidents pending notification.
func (r *PostgresAIIncidentRepository) GetPendingNotifications(ctx context.Context, orgID string, notificationType string) ([]*AIIncident, error) {
	var query string
	switch notificationType {
	case "board":
		query = `
			SELECT
				id, org_id, incident_id, system_id,
				incident_type, severity,
				detected_at, detected_by, detection_details,
				title, description, root_cause,
				affected_customers_count, affected_transactions_count,
				financial_impact_inr, reputational_impact,
				remediation_actions, immediate_action_taken, long_term_fix,
				status, resolved_at, resolution_summary, lessons_learned,
				board_notification_required, board_notified,
				board_notification_date, board_notification_reference,
				rbi_notification_required, rbi_notified,
				rbi_notification_date, rbi_notification_reference, rbi_response,
				evidence_files, tags, metadata,
				created_at, updated_at
			FROM rbi_ai_incidents
			WHERE org_id = $1 AND board_notification_required = true AND board_notified = false
			ORDER BY severity, detected_at
		`
	case "rbi":
		query = `
			SELECT
				id, org_id, incident_id, system_id,
				incident_type, severity,
				detected_at, detected_by, detection_details,
				title, description, root_cause,
				affected_customers_count, affected_transactions_count,
				financial_impact_inr, reputational_impact,
				remediation_actions, immediate_action_taken, long_term_fix,
				status, resolved_at, resolution_summary, lessons_learned,
				board_notification_required, board_notified,
				board_notification_date, board_notification_reference,
				rbi_notification_required, rbi_notified,
				rbi_notification_date, rbi_notification_reference, rbi_response,
				evidence_files, tags, metadata,
				created_at, updated_at
			FROM rbi_ai_incidents
			WHERE org_id = $1 AND rbi_notification_required = true AND rbi_notified = false
			ORDER BY severity, detected_at
		`
	default:
		return nil, fmt.Errorf("invalid notification type: %s", notificationType)
	}

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending notifications: %w", err)
	}
	defer rows.Close()

	var incidents []*AIIncident
	for rows.Next() {
		incident, err := r.scanIncidentRows(rows)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, incident)
	}

	return incidents, rows.Err()
}

// scanIncident scans a single row into an AIIncident.
func (r *PostgresAIIncidentRepository) scanIncident(row *sql.Row) (*AIIncident, error) {
	var incident AIIncident
	var systemID, detectionDetails, rootCause sql.NullString
	var reputationalImpact, immediateActionTaken, longTermFix sql.NullString
	var resolutionSummary, lessonsLearned sql.NullString
	var boardNotificationReference, rbiNotificationReference, rbiResponse sql.NullString
	var affectedCustomers, affectedTransactions sql.NullInt64
	var financialImpact sql.NullFloat64
	var resolvedAt, boardNotificationDate, rbiNotificationDate sql.NullTime
	var remediationActionsJSON, evidenceFilesJSON, tagsJSON, metadataJSON []byte

	err := row.Scan(
		&incident.ID, &incident.OrgID, &incident.IncidentID, &systemID,
		&incident.IncidentType, &incident.Severity,
		&incident.DetectedAt, &incident.DetectedBy, &detectionDetails,
		&incident.Title, &incident.Description, &rootCause,
		&affectedCustomers, &affectedTransactions,
		&financialImpact, &reputationalImpact,
		&remediationActionsJSON, &immediateActionTaken, &longTermFix,
		&incident.Status, &resolvedAt, &resolutionSummary, &lessonsLearned,
		&incident.BoardNotificationRequired, &incident.BoardNotified,
		&boardNotificationDate, &boardNotificationReference,
		&incident.RBINotificationRequired, &incident.RBINotified,
		&rbiNotificationDate, &rbiNotificationReference, &rbiResponse,
		&evidenceFilesJSON, &tagsJSON, &metadataJSON,
		&incident.CreatedAt, &incident.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan incident: %w", err)
	}

	// Handle nullable fields
	if systemID.Valid {
		incident.SystemID = systemID.String
	}
	if detectionDetails.Valid {
		incident.DetectionDetails = detectionDetails.String
	}
	if rootCause.Valid {
		incident.RootCause = rootCause.String
	}
	if reputationalImpact.Valid {
		incident.ReputationalImpact = reputationalImpact.String
	}
	if immediateActionTaken.Valid {
		incident.ImmediateActionTaken = immediateActionTaken.String
	}
	if longTermFix.Valid {
		incident.LongTermFix = longTermFix.String
	}
	if resolutionSummary.Valid {
		incident.ResolutionSummary = resolutionSummary.String
	}
	if lessonsLearned.Valid {
		incident.LessonsLearned = lessonsLearned.String
	}
	if boardNotificationReference.Valid {
		incident.BoardNotificationReference = boardNotificationReference.String
	}
	if rbiNotificationReference.Valid {
		incident.RBINotificationReference = rbiNotificationReference.String
	}
	if rbiResponse.Valid {
		incident.RBIResponse = rbiResponse.String
	}
	if affectedCustomers.Valid {
		val := int(affectedCustomers.Int64)
		incident.AffectedCustomersCount = &val
	}
	if affectedTransactions.Valid {
		val := int(affectedTransactions.Int64)
		incident.AffectedTransactionsCount = &val
	}
	if financialImpact.Valid {
		incident.FinancialImpactINR = &financialImpact.Float64
	}
	if resolvedAt.Valid {
		incident.ResolvedAt = &resolvedAt.Time
	}
	if boardNotificationDate.Valid {
		incident.BoardNotificationDate = &boardNotificationDate.Time
	}
	if rbiNotificationDate.Valid {
		incident.RBINotificationDate = &rbiNotificationDate.Time
	}

	// Unmarshal JSON fields
	if len(remediationActionsJSON) > 0 {
		json.Unmarshal(remediationActionsJSON, &incident.RemediationActions)
	}
	if len(evidenceFilesJSON) > 0 {
		json.Unmarshal(evidenceFilesJSON, &incident.EvidenceFiles)
	}
	if len(tagsJSON) > 0 {
		json.Unmarshal(tagsJSON, &incident.Tags)
	}
	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &incident.Metadata)
	}

	return &incident, nil
}

// scanIncidentRows scans a row from rows into an AIIncident.
func (r *PostgresAIIncidentRepository) scanIncidentRows(rows *sql.Rows) (*AIIncident, error) {
	var incident AIIncident
	var systemID, detectionDetails, rootCause sql.NullString
	var reputationalImpact, immediateActionTaken, longTermFix sql.NullString
	var resolutionSummary, lessonsLearned sql.NullString
	var boardNotificationReference, rbiNotificationReference, rbiResponse sql.NullString
	var affectedCustomers, affectedTransactions sql.NullInt64
	var financialImpact sql.NullFloat64
	var resolvedAt, boardNotificationDate, rbiNotificationDate sql.NullTime
	var remediationActionsJSON, evidenceFilesJSON, tagsJSON, metadataJSON []byte

	err := rows.Scan(
		&incident.ID, &incident.OrgID, &incident.IncidentID, &systemID,
		&incident.IncidentType, &incident.Severity,
		&incident.DetectedAt, &incident.DetectedBy, &detectionDetails,
		&incident.Title, &incident.Description, &rootCause,
		&affectedCustomers, &affectedTransactions,
		&financialImpact, &reputationalImpact,
		&remediationActionsJSON, &immediateActionTaken, &longTermFix,
		&incident.Status, &resolvedAt, &resolutionSummary, &lessonsLearned,
		&incident.BoardNotificationRequired, &incident.BoardNotified,
		&boardNotificationDate, &boardNotificationReference,
		&incident.RBINotificationRequired, &incident.RBINotified,
		&rbiNotificationDate, &rbiNotificationReference, &rbiResponse,
		&evidenceFilesJSON, &tagsJSON, &metadataJSON,
		&incident.CreatedAt, &incident.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan incident row: %w", err)
	}

	// Handle nullable fields
	if systemID.Valid {
		incident.SystemID = systemID.String
	}
	if detectionDetails.Valid {
		incident.DetectionDetails = detectionDetails.String
	}
	if rootCause.Valid {
		incident.RootCause = rootCause.String
	}
	if reputationalImpact.Valid {
		incident.ReputationalImpact = reputationalImpact.String
	}
	if immediateActionTaken.Valid {
		incident.ImmediateActionTaken = immediateActionTaken.String
	}
	if longTermFix.Valid {
		incident.LongTermFix = longTermFix.String
	}
	if resolutionSummary.Valid {
		incident.ResolutionSummary = resolutionSummary.String
	}
	if lessonsLearned.Valid {
		incident.LessonsLearned = lessonsLearned.String
	}
	if boardNotificationReference.Valid {
		incident.BoardNotificationReference = boardNotificationReference.String
	}
	if rbiNotificationReference.Valid {
		incident.RBINotificationReference = rbiNotificationReference.String
	}
	if rbiResponse.Valid {
		incident.RBIResponse = rbiResponse.String
	}
	if affectedCustomers.Valid {
		val := int(affectedCustomers.Int64)
		incident.AffectedCustomersCount = &val
	}
	if affectedTransactions.Valid {
		val := int(affectedTransactions.Int64)
		incident.AffectedTransactionsCount = &val
	}
	if financialImpact.Valid {
		incident.FinancialImpactINR = &financialImpact.Float64
	}
	if resolvedAt.Valid {
		incident.ResolvedAt = &resolvedAt.Time
	}
	if boardNotificationDate.Valid {
		incident.BoardNotificationDate = &boardNotificationDate.Time
	}
	if rbiNotificationDate.Valid {
		incident.RBINotificationDate = &rbiNotificationDate.Time
	}

	// Unmarshal JSON fields
	if len(remediationActionsJSON) > 0 {
		json.Unmarshal(remediationActionsJSON, &incident.RemediationActions)
	}
	if len(evidenceFilesJSON) > 0 {
		json.Unmarshal(evidenceFilesJSON, &incident.EvidenceFiles)
	}
	if len(tagsJSON) > 0 {
		json.Unmarshal(tagsJSON, &incident.Tags)
	}
	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &incident.Metadata)
	}

	return &incident, nil
}

// nullString converts a string to sql.NullString.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullTime converts *time.Time to sql.NullTime.
func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// nullInt converts *int to sql.NullInt64.
func nullInt(val *int) sql.NullInt64 {
	if val == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*val), Valid: true}
}

// nullFloat64 converts *float64 to sql.NullFloat64.
func nullFloat64(val *float64) sql.NullFloat64 {
	if val == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *val, Valid: true}
}
