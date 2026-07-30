// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/shared/tenantscope"
)

// Repository defines the interface for plan storage
type Repository interface {
	// SavePlan stores a new plan
	SavePlan(ctx context.Context, plan *Plan) error

	// GetPlan retrieves a plan by ID
	GetPlan(ctx context.Context, planID string) (*Plan, error)

	// UpdatePlanStatus updates the status and optionally the execution result
	UpdatePlanStatus(ctx context.Context, planID string, status PlanStatus, result json.RawMessage, errorMsg string) error

	// UpdatePlanStatusAtomic atomically updates status only if current status matches expected
	// Returns ErrPlanAlreadyRun if the status doesn't match (race condition prevention)
	UpdatePlanStatusAtomic(ctx context.Context, planID string, expectedStatus, newStatus PlanStatus) error

	// DeletePlan removes a plan
	DeletePlan(ctx context.Context, planID string) error

	// CleanupExpiredPlans removes expired plans
	CleanupExpiredPlans(ctx context.Context) (int, error)

	// UpdatePlanWithVersion updates a plan with optimistic locking.
	// Returns ErrVersionConflict if the current version doesn't match expectedVersion.
	UpdatePlanWithVersion(ctx context.Context, planID string, expectedVersion int, updates map[string]interface{}) (*Plan, error)

	// SavePlanVersion saves a snapshot of a plan at a specific version
	SavePlanVersion(ctx context.Context, version *PlanVersion) error

	// GetPlanVersions retrieves all versions for a plan, ordered by version desc
	GetPlanVersions(ctx context.Context, planID string) ([]PlanVersion, error)

	// CountPlansWithVersioning returns the number of plans that have versioning enabled (version > 1)
	CountPlansWithVersioning(ctx context.Context, orgID string) (int, error)

	// CountVersions returns the number of versions for a plan
	CountVersions(ctx context.Context, planID string) (int, error)

	// GetPlanVersion retrieves a specific version snapshot for a plan
	GetPlanVersion(ctx context.Context, planID string, version int) (*PlanVersion, error)

	// RollbackPlan restores a plan from a snapshot, incrementing the version.
	// Returns ErrVersionConflict if currentVersion doesn't match expectedVersion.
	RollbackPlan(ctx context.Context, planID string, expectedVersion int, snapshot json.RawMessage) (*Plan, error)
}

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// Ensure PostgresRepository implements Repository
var _ Repository = (*PostgresRepository)(nil)

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// SavePlan stores a new plan in the database
func (r *PostgresRepository) SavePlan(ctx context.Context, plan *Plan) error {
	if plan == nil || plan.PlanID == "" {
		return ErrInvalidPlanID
	}

	// #3065 (F2): refuse to persist a plan with no tenancy key. The columns
	// below go through nullString(), which silently turns an absent header
	// into a permanent NULL — and `plans` has no RLS, so that NULL was the
	// whole story. Service.StorePlan validates too; this is the layer a
	// future caller cannot skip.
	if err := tenantscope.ValidateRowKeys(plan.OrgID, plan.TenantID); err != nil {
		return fmt.Errorf("refusing to persist plan %s with no org/tenant key: %w", plan.PlanID, err)
	}

	query := `
		INSERT INTO plans (
			plan_id, query, domain, execution_mode, version,
			workflow_definition,
			complexity, parallel, estimated_duration, step_count,
			status,
			org_id, tenant_id, user_id, client_id,
			expires_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6,
			$7, $8, $9, $10,
			$11,
			$12, $13, $14, $15,
			$16
		)`

	version := plan.Version
	if version == 0 {
		version = 1
	}

	_, err := r.db.ExecContext(ctx, query,
		plan.PlanID, plan.Query, plan.Domain, plan.ExecutionMode, version,
		plan.WorkflowDefinition,
		plan.Complexity, plan.Parallel, plan.EstimatedDuration, plan.StepCount,
		string(plan.Status),
		nullString(plan.OrgID), nullString(plan.TenantID), nullString(plan.UserID), nullString(plan.ClientID),
		plan.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to save plan: %w", err)
	}

	return nil
}

// GetPlan retrieves a plan by ID
func (r *PostgresRepository) GetPlan(ctx context.Context, planID string) (*Plan, error) {
	if planID == "" {
		return nil, ErrInvalidPlanID
	}

	query := `
		SELECT plan_id, query, domain, execution_mode, COALESCE(version, 1),
			workflow_definition,
			complexity, parallel, estimated_duration, step_count,
			status, executed_at, execution_result, error_message,
			org_id, tenant_id, user_id, client_id,
			expires_at, created_at, updated_at
		FROM plans
		WHERE plan_id = $1`

	plan := &Plan{}
	var status string
	var executedAt sql.NullTime
	var executionResult, estimatedDuration sql.NullString
	var errorMessage sql.NullString
	var orgID, tenantID, userID, clientID sql.NullString

	err := r.db.QueryRowContext(ctx, query, planID).Scan(
		&plan.PlanID, &plan.Query, &plan.Domain, &plan.ExecutionMode, &plan.Version,
		&plan.WorkflowDefinition,
		&plan.Complexity, &plan.Parallel, &estimatedDuration, &plan.StepCount,
		&status, &executedAt, &executionResult, &errorMessage,
		&orgID, &tenantID, &userID, &clientID,
		&plan.ExpiresAt, &plan.CreatedAt, &plan.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrPlanNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get plan: %w", err)
	}

	plan.Status = PlanStatus(status)

	if executedAt.Valid {
		plan.ExecutedAt = &executedAt.Time
	}
	if executionResult.Valid {
		plan.ExecutionResult = json.RawMessage(executionResult.String)
	}
	if estimatedDuration.Valid {
		plan.EstimatedDuration = estimatedDuration.String
	}
	if errorMessage.Valid {
		plan.ErrorMessage = errorMessage.String
	}
	if orgID.Valid {
		plan.OrgID = orgID.String
	}
	if tenantID.Valid {
		plan.TenantID = tenantID.String
	}
	if userID.Valid {
		plan.UserID = userID.String
	}
	if clientID.Valid {
		plan.ClientID = clientID.String
	}

	return plan, nil
}

// UpdatePlanStatus updates the status and optionally the execution result
func (r *PostgresRepository) UpdatePlanStatus(ctx context.Context, planID string, status PlanStatus, result json.RawMessage, errorMsg string) error {
	if planID == "" {
		return ErrInvalidPlanID
	}

	var query string
	var args []interface{}

	if status == PlanStatusCompleted || status == PlanStatusFailed {
		// Include executed_at and result
		query = `
			UPDATE plans
			SET status = $1, executed_at = $2, execution_result = $3, error_message = $4
			WHERE plan_id = $5`
		args = []interface{}{string(status), time.Now(), nullJSON(result), nullString(errorMsg), planID}
	} else {
		// Just update status
		query = `UPDATE plans SET status = $1, updated_at = NOW() WHERE plan_id = $2`
		args = []interface{}{string(status), planID}
	}

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update plan status: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrPlanNotFound
	}

	return nil
}

// UpdatePlanStatusAtomic atomically updates status only if current status matches expected
// This prevents race conditions when multiple ExecutePlan requests arrive simultaneously
func (r *PostgresRepository) UpdatePlanStatusAtomic(ctx context.Context, planID string, expectedStatus, newStatus PlanStatus) error {
	if planID == "" {
		return ErrInvalidPlanID
	}

	query := `UPDATE plans SET status = $1, updated_at = NOW() WHERE plan_id = $2 AND status = $3`
	res, err := r.db.ExecContext(ctx, query, string(newStatus), planID, string(expectedStatus))
	if err != nil {
		return fmt.Errorf("failed to update plan status atomically: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		// Either plan not found or status didn't match (race condition)
		return ErrPlanAlreadyRun
	}

	return nil
}

// DeletePlan removes a plan from the database
func (r *PostgresRepository) DeletePlan(ctx context.Context, planID string) error {
	if planID == "" {
		return ErrInvalidPlanID
	}

	_, err := r.db.ExecContext(ctx, "DELETE FROM plans WHERE plan_id = $1", planID)
	if err != nil {
		return fmt.Errorf("failed to delete plan: %w", err)
	}
	return nil
}

// CleanupExpiredPlans removes expired plans and returns the count of deleted plans
func (r *PostgresRepository) CleanupExpiredPlans(ctx context.Context) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM plans
		WHERE expires_at < CURRENT_TIMESTAMP
		AND status IN ('pending', 'expired')
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired plans: %w", err)
	}

	count, _ := res.RowsAffected()
	return int(count), nil
}

// UpdatePlanWithVersion updates a plan with optimistic locking
func (r *PostgresRepository) UpdatePlanWithVersion(ctx context.Context, planID string, expectedVersion int, updates map[string]interface{}) (*Plan, error) {
	if planID == "" {
		return nil, ErrInvalidPlanID
	}

	// Build dynamic SET clause from updates
	allowedColumns := map[string]bool{"execution_mode": true, "domain": true}
	setClauses := []string{"version = version + 1", "updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	for col, val := range updates {
		if !allowedColumns[col] {
			return nil, fmt.Errorf("invalid update column: %s", col)
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col, argIdx))
		args = append(args, val)
		argIdx++
	}

	// Add WHERE conditions
	query := fmt.Sprintf(
		"UPDATE plans SET %s WHERE plan_id = $%d AND version = $%d RETURNING version",
		strings.Join(setClauses, ", "), argIdx, argIdx+1,
	)
	args = append(args, planID, expectedVersion)

	var newVersion int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&newVersion)
	if err == sql.ErrNoRows {
		return nil, ErrVersionConflict
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update plan: %w", err)
	}

	// Return the updated plan
	return r.GetPlan(ctx, planID)
}

// SavePlanVersion saves a version snapshot
func (r *PostgresRepository) SavePlanVersion(ctx context.Context, version *PlanVersion) error {
	query := `
		INSERT INTO plan_versions (plan_id, version, org_id, snapshot, changed_by, change_type, change_summary)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.ExecContext(ctx, query,
		version.PlanID, version.Version, nullString(version.OrgID), version.Snapshot,
		nullString(version.ChangedBy), version.ChangeType, nullString(version.ChangeSummary),
	)
	if err != nil {
		return fmt.Errorf("failed to save plan version: %w", err)
	}
	return nil
}

// GetPlanVersions retrieves all versions for a plan
func (r *PostgresRepository) GetPlanVersions(ctx context.Context, planID string) ([]PlanVersion, error) {
	if planID == "" {
		return nil, ErrInvalidPlanID
	}

	query := `
		SELECT id, plan_id, version, COALESCE(org_id, ''), snapshot, COALESCE(changed_by, ''), changed_at, change_type, COALESCE(change_summary, '')
		FROM plan_versions
		WHERE plan_id = $1
		ORDER BY version DESC`

	rows, err := r.db.QueryContext(ctx, query, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan versions: %w", err)
	}
	defer rows.Close()

	var versions []PlanVersion
	for rows.Next() {
		var v PlanVersion
		if err := rows.Scan(&v.ID, &v.PlanID, &v.Version, &v.OrgID, &v.Snapshot, &v.ChangedBy, &v.ChangedAt, &v.ChangeType, &v.ChangeSummary); err != nil {
			return nil, fmt.Errorf("failed to scan plan version: %w", err)
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// CountPlansWithVersioning returns the number of plans with version > 1 for an org
func (r *PostgresRepository) CountPlansWithVersioning(ctx context.Context, orgID string) (int, error) {
	query := `SELECT COUNT(*) FROM plans WHERE org_id = $1 AND version > 1`
	var count int
	if err := r.db.QueryRowContext(ctx, query, orgID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count versioned plans: %w", err)
	}
	return count, nil
}

// CountVersions returns the number of versions for a plan
func (r *PostgresRepository) CountVersions(ctx context.Context, planID string) (int, error) {
	query := `SELECT COUNT(*) FROM plan_versions WHERE plan_id = $1`
	var count int
	if err := r.db.QueryRowContext(ctx, query, planID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count plan versions: %w", err)
	}
	return count, nil
}

// GetPlanVersion retrieves a specific version snapshot for a plan
func (r *PostgresRepository) GetPlanVersion(ctx context.Context, planID string, version int) (*PlanVersion, error) {
	if planID == "" {
		return nil, ErrInvalidPlanID
	}

	query := `
		SELECT id, plan_id, version, COALESCE(org_id, ''), snapshot, COALESCE(changed_by, ''), changed_at, change_type, COALESCE(change_summary, '')
		FROM plan_versions
		WHERE plan_id = $1 AND version = $2`

	var v PlanVersion
	err := r.db.QueryRowContext(ctx, query, planID, version).Scan(
		&v.ID, &v.PlanID, &v.Version, &v.OrgID, &v.Snapshot, &v.ChangedBy, &v.ChangedAt, &v.ChangeType, &v.ChangeSummary,
	)
	if err == sql.ErrNoRows {
		return nil, ErrVersionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get plan version: %w", err)
	}
	return &v, nil
}

// RollbackPlan restores a plan from a snapshot, incrementing the version.
func (r *PostgresRepository) RollbackPlan(ctx context.Context, planID string, expectedVersion int, snapshot json.RawMessage) (*Plan, error) {
	if planID == "" {
		return nil, ErrInvalidPlanID
	}

	// Parse the snapshot to extract restorable fields
	var snap struct {
		ExecutionMode      string          `json:"execution_mode"`
		Domain             string          `json:"domain"`
		WorkflowDefinition json.RawMessage `json:"workflow_definition"`
	}
	if err := json.Unmarshal(snapshot, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse version snapshot: %w", err)
	}

	query := `
		UPDATE plans
		SET execution_mode = $1, domain = $2, workflow_definition = $3,
			version = version + 1, updated_at = NOW()
		WHERE plan_id = $4 AND version = $5
		RETURNING version`

	var newVersion int
	err := r.db.QueryRowContext(ctx, query,
		snap.ExecutionMode, snap.Domain, snap.WorkflowDefinition,
		planID, expectedVersion,
	).Scan(&newVersion)
	if err == sql.ErrNoRows {
		return nil, ErrVersionConflict
	}
	if err != nil {
		return nil, fmt.Errorf("failed to rollback plan: %w", err)
	}

	return r.GetPlan(ctx, planID)
}

// NoOpRepository is a no-op implementation of Repository for testing
// This is used when database is not available
type NoOpRepository struct{}

// Ensure NoOpRepository implements Repository
var _ Repository = (*NoOpRepository)(nil)

// NewNoOpRepository creates a new no-op repository
func NewNoOpRepository() *NoOpRepository {
	return &NoOpRepository{}
}

// SavePlan is a no-op
func (r *NoOpRepository) SavePlan(ctx context.Context, plan *Plan) error {
	return nil
}

// GetPlan returns ErrPlanNotFound
func (r *NoOpRepository) GetPlan(ctx context.Context, planID string) (*Plan, error) {
	return nil, ErrPlanNotFound
}

// UpdatePlanStatus is a no-op
func (r *NoOpRepository) UpdatePlanStatus(ctx context.Context, planID string, status PlanStatus, result json.RawMessage, errorMsg string) error {
	return nil
}

// UpdatePlanStatusAtomic is a no-op
func (r *NoOpRepository) UpdatePlanStatusAtomic(ctx context.Context, planID string, expectedStatus, newStatus PlanStatus) error {
	return nil
}

// DeletePlan is a no-op
func (r *NoOpRepository) DeletePlan(ctx context.Context, planID string) error {
	return nil
}

// CleanupExpiredPlans returns 0
func (r *NoOpRepository) CleanupExpiredPlans(ctx context.Context) (int, error) {
	return 0, nil
}

// UpdatePlanWithVersion is a no-op
func (r *NoOpRepository) UpdatePlanWithVersion(ctx context.Context, planID string, expectedVersion int, updates map[string]interface{}) (*Plan, error) {
	return nil, ErrPlanNotFound
}

// SavePlanVersion is a no-op
func (r *NoOpRepository) SavePlanVersion(ctx context.Context, version *PlanVersion) error {
	return nil
}

// GetPlanVersions returns empty
func (r *NoOpRepository) GetPlanVersions(ctx context.Context, planID string) ([]PlanVersion, error) {
	return nil, nil
}

// CountPlansWithVersioning returns 0
func (r *NoOpRepository) CountPlansWithVersioning(ctx context.Context, orgID string) (int, error) {
	return 0, nil
}

// CountVersions returns 0
func (r *NoOpRepository) CountVersions(ctx context.Context, planID string) (int, error) {
	return 0, nil
}

// GetPlanVersion returns ErrVersionNotFound
func (r *NoOpRepository) GetPlanVersion(ctx context.Context, planID string, version int) (*PlanVersion, error) {
	return nil, ErrVersionNotFound
}

// RollbackPlan returns ErrPlanNotFound
func (r *NoOpRepository) RollbackPlan(ctx context.Context, planID string, expectedVersion int, snapshot json.RawMessage) (*Plan, error) {
	return nil, ErrPlanNotFound
}

// Helper functions

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullJSON(data json.RawMessage) sql.NullString {
	if len(data) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(data), Valid: true}
}
