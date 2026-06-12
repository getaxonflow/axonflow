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

// Common errors for the registry.
var (
	ErrSystemNotFound      = errors.New("AI system not found")
	ErrSystemAlreadyExists = errors.New("AI system with this ID already exists")
	ErrInvalidInput        = errors.New("invalid input")
)

// AISystemRepository provides data access for AI system registry.
type AISystemRepository interface {
	// Create creates a new AI system in the registry.
	Create(ctx context.Context, system *AISystem) error

	// Get retrieves an AI system by ID.
	Get(ctx context.Context, orgID, id string) (*AISystem, error)

	// GetBySystemID retrieves an AI system by system_id.
	GetBySystemID(ctx context.Context, orgID, systemID string) (*AISystem, error)

	// List retrieves AI systems with optional filtering.
	List(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error)

	// Update updates an AI system.
	Update(ctx context.Context, system *AISystem) error

	// Delete soft-deletes an AI system (marks as deprecated).
	Delete(ctx context.Context, orgID, id string) error

	// GetSummary returns summary statistics for AI systems.
	GetSummary(ctx context.Context, orgID string) (*AISystemSummary, error)
}

// PostgresAISystemRepository implements AISystemRepository using PostgreSQL.
type PostgresAISystemRepository struct {
	db *sql.DB
}

// NewPostgresAISystemRepository creates a new PostgreSQL-backed repository.
func NewPostgresAISystemRepository(db *sql.DB) *PostgresAISystemRepository {
	return &PostgresAISystemRepository{db: db}
}

// Create creates a new AI system in the registry.
func (r *PostgresAISystemRepository) Create(ctx context.Context, system *AISystem) error {
	if system.ID == "" {
		system.ID = uuid.New().String()
	}
	if system.CreatedAt.IsZero() {
		system.CreatedAt = time.Now().UTC()
	}
	system.UpdatedAt = system.CreatedAt

	// Default deployment status
	if system.DeploymentStatus == "" {
		system.DeploymentStatus = DeploymentStatusDevelopment
	}

	// Determine board approval requirement based on risk category
	if system.RiskCategory == RiskCategoryHigh {
		system.BoardApprovalRequired = true
		if system.BoardApprovalStatus == "" {
			system.BoardApprovalStatus = BoardApprovalPending
		}
	} else if system.BoardApprovalStatus == "" {
		system.BoardApprovalStatus = BoardApprovalNotRequired
	}

	// Serialize JSON fields
	dataSourcesJSON, err := json.Marshal(system.DataSources)
	if err != nil {
		return fmt.Errorf("marshal data_sources: %w", err)
	}

	sensitiveDataJSON, err := json.Marshal(system.SensitiveDataCategories)
	if err != nil {
		return fmt.Errorf("marshal sensitive_data_categories: %w", err)
	}

	tagsJSON, err := json.Marshal(system.Tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(system.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	// board_approval_required is a GENERATED ALWAYS STORED column
	// (`risk_category = 'high'`) per migration
	// 301_rbi_free_ai_compliance.sql — Postgres rejects any explicit
	// value with "cannot insert a non-DEFAULT value into column
	// board_approval_required", so every AI system registration failed
	// before this change. The Go struct field is still populated at
	// scan time; the service-layer assignment kept the business logic
	// self-consistent before the DB rejected the write, but the DB
	// always owns the authoritative value.
	query := `
		INSERT INTO rbi_ai_system_registry (
			id, org_id, system_id, system_name, system_version, description,
			risk_category, deployment_status, model_type, model_provider,
			use_case, use_case_description, data_sources, sensitive_data_categories,
			data_residency, owner_id, owner_name, owner_department, owner_email,
			board_approval_status, board_approval_date,
			board_approval_reference, board_approver_name, board_approval_notes,
			last_validation_date, next_validation_due, validation_frequency_days,
			tags, metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17, $18, $19,
			$20, $21,
			$22, $23, $24,
			$25, $26, $27,
			$28, $29, $30, $31
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		system.ID, system.OrgID, system.SystemID, system.SystemName, system.Version, system.Description,
		system.RiskCategory, system.DeploymentStatus, system.ModelType, system.ModelProvider,
		system.UseCase, system.UseCaseDescription, dataSourcesJSON, sensitiveDataJSON,
		system.DataResidency, system.OwnerID, system.OwnerName, system.OwnerDepartment, system.OwnerEmail,
		system.BoardApprovalStatus, system.BoardApprovalDate,
		system.BoardApprovalReference, system.BoardApproverName, system.BoardApprovalNotes,
		system.LastValidationDate, system.NextValidationDue, system.ValidationFrequencyDays,
		tagsJSON, metadataJSON, system.CreatedAt, system.UpdatedAt,
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return ErrSystemAlreadyExists
		}
		return fmt.Errorf("insert AI system: %w", err)
	}

	return nil
}

// Get retrieves an AI system by ID.
func (r *PostgresAISystemRepository) Get(ctx context.Context, orgID, id string) (*AISystem, error) {
	query := `
		SELECT
			id, org_id, system_id, system_name, system_version, description,
			risk_category, deployment_status, model_type, model_provider,
			use_case, use_case_description, data_sources, sensitive_data_categories,
			data_residency, owner_id, owner_name, owner_department, owner_email,
			board_approval_required, board_approval_status, board_approval_date,
			board_approval_reference, board_approver_name, board_approval_notes,
			last_validation_date, next_validation_due, validation_frequency_days,
			tags, metadata, created_at, updated_at, deprecated_at
		FROM rbi_ai_system_registry
		WHERE org_id = $1 AND id = $2
	`

	return r.scanSystem(r.db.QueryRowContext(ctx, query, orgID, id))
}

// GetBySystemID retrieves an AI system by system_id.
func (r *PostgresAISystemRepository) GetBySystemID(ctx context.Context, orgID, systemID string) (*AISystem, error) {
	query := `
		SELECT
			id, org_id, system_id, system_name, system_version, description,
			risk_category, deployment_status, model_type, model_provider,
			use_case, use_case_description, data_sources, sensitive_data_categories,
			data_residency, owner_id, owner_name, owner_department, owner_email,
			board_approval_required, board_approval_status, board_approval_date,
			board_approval_reference, board_approver_name, board_approval_notes,
			last_validation_date, next_validation_due, validation_frequency_days,
			tags, metadata, created_at, updated_at, deprecated_at
		FROM rbi_ai_system_registry
		WHERE org_id = $1 AND system_id = $2
	`

	return r.scanSystem(r.db.QueryRowContext(ctx, query, orgID, systemID))
}

// scanSystem scans a single row into an AISystem struct.
func (r *PostgresAISystemRepository) scanSystem(row *sql.Row) (*AISystem, error) {
	var system AISystem
	var dataSourcesJSON, sensitiveDataJSON, tagsJSON, metadataJSON []byte
	var version, description, modelType, modelProvider sql.NullString
	var useCase, useCaseDescription, dataResidency sql.NullString
	var ownerID, ownerName, ownerDepartment, ownerEmail sql.NullString
	var boardApprovalReference, boardApproverName, boardApprovalNotes sql.NullString
	var boardApprovalDate, lastValidationDate, nextValidationDue, deprecatedAt sql.NullTime
	var validationFrequencyDays sql.NullInt32

	err := row.Scan(
		&system.ID, &system.OrgID, &system.SystemID, &system.SystemName, &version, &description,
		&system.RiskCategory, &system.DeploymentStatus, &modelType, &modelProvider,
		&useCase, &useCaseDescription, &dataSourcesJSON, &sensitiveDataJSON,
		&dataResidency, &ownerID, &ownerName, &ownerDepartment, &ownerEmail,
		&system.BoardApprovalRequired, &system.BoardApprovalStatus, &boardApprovalDate,
		&boardApprovalReference, &boardApproverName, &boardApprovalNotes,
		&lastValidationDate, &nextValidationDue, &validationFrequencyDays,
		&tagsJSON, &metadataJSON, &system.CreatedAt, &system.UpdatedAt, &deprecatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSystemNotFound
		}
		return nil, fmt.Errorf("scan AI system: %w", err)
	}

	// Handle nullable fields
	if version.Valid {
		system.Version = version.String
	}
	if description.Valid {
		system.Description = description.String
	}
	if modelType.Valid {
		system.ModelType = modelType.String
	}
	if modelProvider.Valid {
		system.ModelProvider = modelProvider.String
	}
	if useCase.Valid {
		system.UseCase = useCase.String
	}
	if useCaseDescription.Valid {
		system.UseCaseDescription = useCaseDescription.String
	}
	if dataResidency.Valid {
		system.DataResidency = dataResidency.String
	}
	if ownerID.Valid {
		system.OwnerID = ownerID.String
	}
	if ownerName.Valid {
		system.OwnerName = ownerName.String
	}
	if ownerDepartment.Valid {
		system.OwnerDepartment = ownerDepartment.String
	}
	if ownerEmail.Valid {
		system.OwnerEmail = ownerEmail.String
	}
	if boardApprovalReference.Valid {
		system.BoardApprovalReference = boardApprovalReference.String
	}
	if boardApproverName.Valid {
		system.BoardApproverName = boardApproverName.String
	}
	if boardApprovalNotes.Valid {
		system.BoardApprovalNotes = boardApprovalNotes.String
	}
	if boardApprovalDate.Valid {
		system.BoardApprovalDate = &boardApprovalDate.Time
	}
	if lastValidationDate.Valid {
		system.LastValidationDate = &lastValidationDate.Time
	}
	if nextValidationDue.Valid {
		system.NextValidationDue = &nextValidationDue.Time
	}
	if deprecatedAt.Valid {
		system.DeprecatedAt = &deprecatedAt.Time
	}
	if validationFrequencyDays.Valid {
		system.ValidationFrequencyDays = int(validationFrequencyDays.Int32)
	}

	// Parse JSON fields
	if len(dataSourcesJSON) > 0 {
		if err := json.Unmarshal(dataSourcesJSON, &system.DataSources); err != nil {
			return nil, fmt.Errorf("unmarshal data_sources: %w", err)
		}
	}
	if len(sensitiveDataJSON) > 0 {
		if err := json.Unmarshal(sensitiveDataJSON, &system.SensitiveDataCategories); err != nil {
			return nil, fmt.Errorf("unmarshal sensitive_data_categories: %w", err)
		}
	}
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &system.Tags); err != nil {
			return nil, fmt.Errorf("unmarshal tags: %w", err)
		}
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &system.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}

	return &system, nil
}

// List retrieves AI systems with optional filtering.
func (r *PostgresAISystemRepository) List(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error) {
	if params == nil {
		params = &ListAISystemsParams{}
	}

	// Set defaults
	if params.Limit <= 0 {
		params.Limit = 20
	}
	if params.Limit > 100 {
		params.Limit = 100
	}

	// Build query
	baseQuery := `
		FROM rbi_ai_system_registry
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIdx := 2

	// Apply filters
	if params.RiskCategory != "" {
		baseQuery += fmt.Sprintf(" AND risk_category = $%d", argIdx)
		args = append(args, params.RiskCategory)
		argIdx++
	}
	if params.DeploymentStatus != "" {
		baseQuery += fmt.Sprintf(" AND deployment_status = $%d", argIdx)
		args = append(args, params.DeploymentStatus)
		argIdx++
	}
	if params.BoardApprovalStatus != "" {
		baseQuery += fmt.Sprintf(" AND board_approval_status = $%d", argIdx)
		args = append(args, params.BoardApprovalStatus)
		argIdx++
	}
	if params.OwnerDepartment != "" {
		baseQuery += fmt.Sprintf(" AND owner_department = $%d", argIdx)
		args = append(args, params.OwnerDepartment)
		argIdx++
	}
	if params.ValidationOverdue != nil && *params.ValidationOverdue {
		baseQuery += " AND next_validation_due < NOW()"
	}

	// Get total count
	countQuery := "SELECT COUNT(*) " + baseQuery
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count AI systems: %w", err)
	}

	// Get paginated results
	selectQuery := `
		SELECT
			id, org_id, system_id, system_name, system_version, description,
			risk_category, deployment_status, model_type, model_provider,
			use_case, use_case_description, data_sources, sensitive_data_categories,
			data_residency, owner_id, owner_name, owner_department, owner_email,
			board_approval_required, board_approval_status, board_approval_date,
			board_approval_reference, board_approver_name, board_approval_notes,
			last_validation_date, next_validation_due, validation_frequency_days,
			tags, metadata, created_at, updated_at, deprecated_at
	` + baseQuery + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, params.Limit, params.Offset)

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query AI systems: %w", err)
	}
	defer rows.Close()

	var systems []*AISystem
	for rows.Next() {
		system, err := r.scanSystemRow(rows)
		if err != nil {
			return nil, 0, err
		}
		systems = append(systems, system)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate AI systems: %w", err)
	}

	return systems, total, nil
}

// scanSystemRow scans a row from a rows iterator into an AISystem struct.
func (r *PostgresAISystemRepository) scanSystemRow(rows *sql.Rows) (*AISystem, error) {
	var system AISystem
	var dataSourcesJSON, sensitiveDataJSON, tagsJSON, metadataJSON []byte
	var version, description, modelType, modelProvider sql.NullString
	var useCase, useCaseDescription, dataResidency sql.NullString
	var ownerID, ownerName, ownerDepartment, ownerEmail sql.NullString
	var boardApprovalReference, boardApproverName, boardApprovalNotes sql.NullString
	var boardApprovalDate, lastValidationDate, nextValidationDue, deprecatedAt sql.NullTime
	var validationFrequencyDays sql.NullInt32

	err := rows.Scan(
		&system.ID, &system.OrgID, &system.SystemID, &system.SystemName, &version, &description,
		&system.RiskCategory, &system.DeploymentStatus, &modelType, &modelProvider,
		&useCase, &useCaseDescription, &dataSourcesJSON, &sensitiveDataJSON,
		&dataResidency, &ownerID, &ownerName, &ownerDepartment, &ownerEmail,
		&system.BoardApprovalRequired, &system.BoardApprovalStatus, &boardApprovalDate,
		&boardApprovalReference, &boardApproverName, &boardApprovalNotes,
		&lastValidationDate, &nextValidationDue, &validationFrequencyDays,
		&tagsJSON, &metadataJSON, &system.CreatedAt, &system.UpdatedAt, &deprecatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("scan AI system row: %w", err)
	}

	// Handle nullable fields (same as scanSystem)
	if version.Valid {
		system.Version = version.String
	}
	if description.Valid {
		system.Description = description.String
	}
	if modelType.Valid {
		system.ModelType = modelType.String
	}
	if modelProvider.Valid {
		system.ModelProvider = modelProvider.String
	}
	if useCase.Valid {
		system.UseCase = useCase.String
	}
	if useCaseDescription.Valid {
		system.UseCaseDescription = useCaseDescription.String
	}
	if dataResidency.Valid {
		system.DataResidency = dataResidency.String
	}
	if ownerID.Valid {
		system.OwnerID = ownerID.String
	}
	if ownerName.Valid {
		system.OwnerName = ownerName.String
	}
	if ownerDepartment.Valid {
		system.OwnerDepartment = ownerDepartment.String
	}
	if ownerEmail.Valid {
		system.OwnerEmail = ownerEmail.String
	}
	if boardApprovalReference.Valid {
		system.BoardApprovalReference = boardApprovalReference.String
	}
	if boardApproverName.Valid {
		system.BoardApproverName = boardApproverName.String
	}
	if boardApprovalNotes.Valid {
		system.BoardApprovalNotes = boardApprovalNotes.String
	}
	if boardApprovalDate.Valid {
		system.BoardApprovalDate = &boardApprovalDate.Time
	}
	if lastValidationDate.Valid {
		system.LastValidationDate = &lastValidationDate.Time
	}
	if nextValidationDue.Valid {
		system.NextValidationDue = &nextValidationDue.Time
	}
	if deprecatedAt.Valid {
		system.DeprecatedAt = &deprecatedAt.Time
	}
	if validationFrequencyDays.Valid {
		system.ValidationFrequencyDays = int(validationFrequencyDays.Int32)
	}

	// Parse JSON fields
	if len(dataSourcesJSON) > 0 {
		if err := json.Unmarshal(dataSourcesJSON, &system.DataSources); err != nil {
			return nil, fmt.Errorf("unmarshal data_sources: %w", err)
		}
	}
	if len(sensitiveDataJSON) > 0 {
		if err := json.Unmarshal(sensitiveDataJSON, &system.SensitiveDataCategories); err != nil {
			return nil, fmt.Errorf("unmarshal sensitive_data_categories: %w", err)
		}
	}
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &system.Tags); err != nil {
			return nil, fmt.Errorf("unmarshal tags: %w", err)
		}
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &system.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}

	return &system, nil
}

// Update updates an AI system.
func (r *PostgresAISystemRepository) Update(ctx context.Context, system *AISystem) error {
	system.UpdatedAt = time.Now().UTC()

	// Serialize JSON fields
	dataSourcesJSON, err := json.Marshal(system.DataSources)
	if err != nil {
		return fmt.Errorf("marshal data_sources: %w", err)
	}

	sensitiveDataJSON, err := json.Marshal(system.SensitiveDataCategories)
	if err != nil {
		return fmt.Errorf("marshal sensitive_data_categories: %w", err)
	}

	tagsJSON, err := json.Marshal(system.Tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(system.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	// board_approval_required is a GENERATED ALWAYS column (see INSERT
	// comment above) — UPDATE must also skip it. Postgres surfaces
	// "column board_approval_required can only be updated to DEFAULT"
	// when it's in the SET list.
	query := `
		UPDATE rbi_ai_system_registry SET
			system_name = $1, system_version = $2, description = $3,
			risk_category = $4, deployment_status = $5, model_type = $6, model_provider = $7,
			use_case = $8, use_case_description = $9, data_sources = $10, sensitive_data_categories = $11,
			data_residency = $12, owner_id = $13, owner_name = $14, owner_department = $15, owner_email = $16,
			board_approval_status = $17, board_approval_date = $18,
			board_approval_reference = $19, board_approver_name = $20, board_approval_notes = $21,
			last_validation_date = $22, next_validation_due = $23, validation_frequency_days = $24,
			tags = $25, metadata = $26, updated_at = $27, deprecated_at = $28
		WHERE org_id = $29 AND id = $30
	`

	result, err := r.db.ExecContext(ctx, query,
		system.SystemName, system.Version, system.Description,
		system.RiskCategory, system.DeploymentStatus, system.ModelType, system.ModelProvider,
		system.UseCase, system.UseCaseDescription, dataSourcesJSON, sensitiveDataJSON,
		system.DataResidency, system.OwnerID, system.OwnerName, system.OwnerDepartment, system.OwnerEmail,
		system.BoardApprovalStatus, system.BoardApprovalDate,
		system.BoardApprovalReference, system.BoardApproverName, system.BoardApprovalNotes,
		system.LastValidationDate, system.NextValidationDue, system.ValidationFrequencyDays,
		tagsJSON, metadataJSON, system.UpdatedAt, system.DeprecatedAt,
		system.OrgID, system.ID,
	)

	if err != nil {
		return fmt.Errorf("update AI system: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrSystemNotFound
	}

	return nil
}

// Delete soft-deletes an AI system (marks as deprecated).
func (r *PostgresAISystemRepository) Delete(ctx context.Context, orgID, id string) error {
	now := time.Now().UTC()
	query := `
		UPDATE rbi_ai_system_registry
		SET deployment_status = $1, deprecated_at = $2, updated_at = $2
		WHERE org_id = $3 AND id = $4
	`

	result, err := r.db.ExecContext(ctx, query, DeploymentStatusDeprecated, now, orgID, id)
	if err != nil {
		return fmt.Errorf("delete AI system: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrSystemNotFound
	}

	return nil
}

// GetSummary returns summary statistics for AI systems.
func (r *PostgresAISystemRepository) GetSummary(ctx context.Context, orgID string) (*AISystemSummary, error) {
	summary := &AISystemSummary{
		SystemsByRisk:   make(map[string]int),
		SystemsByStatus: make(map[string]int),
	}

	// Get total count
	var total int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM rbi_ai_system_registry WHERE org_id = $1
	`, orgID).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("count total systems: %w", err)
	}
	summary.TotalSystems = total

	// Get counts by risk category
	rows, err := r.db.QueryContext(ctx, `
		SELECT risk_category, COUNT(*)
		FROM rbi_ai_system_registry
		WHERE org_id = $1
		GROUP BY risk_category
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("count by risk: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var category string
		var count int
		if err := rows.Scan(&category, &count); err != nil {
			return nil, fmt.Errorf("scan risk count: %w", err)
		}
		summary.SystemsByRisk[category] = count
	}

	// Get counts by deployment status
	rows, err = r.db.QueryContext(ctx, `
		SELECT deployment_status, COUNT(*)
		FROM rbi_ai_system_registry
		WHERE org_id = $1
		GROUP BY deployment_status
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("count by status: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scan status count: %w", err)
		}
		summary.SystemsByStatus[status] = count
	}

	// Get pending approval count
	err = r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM rbi_ai_system_registry
		WHERE org_id = $1 AND board_approval_status = 'pending'
	`, orgID).Scan(&summary.SystemsPendingApproval)
	if err != nil {
		return nil, fmt.Errorf("count pending approval: %w", err)
	}

	// Get overdue validation count
	err = r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM rbi_ai_system_registry
		WHERE org_id = $1 AND next_validation_due < NOW()
	`, orgID).Scan(&summary.SystemsOverdueValidation)
	if err != nil {
		return nil, fmt.Errorf("count overdue validation: %w", err)
	}

	return summary, nil
}
