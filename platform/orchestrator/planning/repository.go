// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
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

	query := `
		INSERT INTO plans (
			plan_id, query, domain, execution_mode,
			workflow_definition,
			complexity, parallel, estimated_duration, step_count,
			status,
			org_id, tenant_id, user_id, client_id,
			expires_at
		) VALUES (
			$1, $2, $3, $4,
			$5,
			$6, $7, $8, $9,
			$10,
			$11, $12, $13, $14,
			$15
		)`

	_, err := r.db.ExecContext(ctx, query,
		plan.PlanID, plan.Query, plan.Domain, plan.ExecutionMode,
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
		SELECT plan_id, query, domain, execution_mode,
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
		&plan.PlanID, &plan.Query, &plan.Domain, &plan.ExecutionMode,
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
		query = `UPDATE plans SET status = $1 WHERE plan_id = $2`
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
