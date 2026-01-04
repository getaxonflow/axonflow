// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

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

// SaveSnapshot saves an execution snapshot to the database
func (r *PostgresRepository) SaveSnapshot(ctx context.Context, snapshot *ExecutionSnapshot) error {
	if snapshot == nil {
		return ErrInvalidInput
	}

	policiesChecked, err := json.Marshal(snapshot.PoliciesChecked)
	if err != nil {
		return fmt.Errorf("failed to marshal policies_checked: %w", err)
	}

	policiesTriggered, err := json.Marshal(snapshot.PoliciesTriggered)
	if err != nil {
		return fmt.Errorf("failed to marshal policies_triggered: %w", err)
	}

	query := `
		INSERT INTO execution_snapshots (
			request_id, step_index, step_name, status,
			started_at, completed_at, duration_ms,
			input, output,
			provider, model, tokens_in, tokens_out, cost_usd,
			policies_checked, policies_triggered,
			error_message, retry_count
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9,
			$10, $11, $12, $13, $14,
			$15, $16,
			$17, $18
		)
		ON CONFLICT (request_id, step_index) DO UPDATE SET
			status = EXCLUDED.status,
			completed_at = EXCLUDED.completed_at,
			duration_ms = EXCLUDED.duration_ms,
			output = EXCLUDED.output,
			provider = EXCLUDED.provider,
			model = EXCLUDED.model,
			tokens_in = EXCLUDED.tokens_in,
			tokens_out = EXCLUDED.tokens_out,
			cost_usd = EXCLUDED.cost_usd,
			policies_checked = EXCLUDED.policies_checked,
			policies_triggered = EXCLUDED.policies_triggered,
			error_message = EXCLUDED.error_message,
			retry_count = EXCLUDED.retry_count
		RETURNING id`

	err = r.db.QueryRowContext(ctx, query,
		snapshot.RequestID, snapshot.StepIndex, snapshot.StepName, string(snapshot.Status),
		snapshot.StartedAt, snapshot.CompletedAt, snapshot.DurationMs,
		toValidJSON(snapshot.Input), toValidJSON(snapshot.Output),
		snapshot.Provider, snapshot.Model, snapshot.TokensIn, snapshot.TokensOut, snapshot.CostUSD,
		policiesChecked, policiesTriggered,
		snapshot.ErrorMessage, snapshot.RetryCount,
	).Scan(&snapshot.ID)

	if err != nil {
		return fmt.Errorf("failed to save snapshot: %w", err)
	}

	return nil
}

// UpdateSnapshot updates an existing snapshot
func (r *PostgresRepository) UpdateSnapshot(ctx context.Context, snapshot *ExecutionSnapshot) error {
	return r.SaveSnapshot(ctx, snapshot) // Upsert handles updates
}

// GetSnapshot retrieves a specific snapshot by request ID and step index
func (r *PostgresRepository) GetSnapshot(ctx context.Context, requestID string, stepIndex int) (*ExecutionSnapshot, error) {
	query := `
		SELECT id, request_id, step_index, step_name, status,
			started_at, completed_at, duration_ms,
			input, output,
			provider, model, tokens_in, tokens_out, cost_usd,
			policies_checked, policies_triggered,
			error_message, retry_count, created_at
		FROM execution_snapshots
		WHERE request_id = $1 AND step_index = $2`

	snapshot := &ExecutionSnapshot{}
	var status string
	var policiesChecked, policiesTriggered []byte
	var completedAt sql.NullTime
	var durationMs sql.NullInt32
	var provider, model, errorMessage sql.NullString

	err := r.db.QueryRowContext(ctx, query, requestID, stepIndex).Scan(
		&snapshot.ID, &snapshot.RequestID, &snapshot.StepIndex, &snapshot.StepName, &status,
		&snapshot.StartedAt, &completedAt, &durationMs,
		&snapshot.Input, &snapshot.Output,
		&provider, &model, &snapshot.TokensIn, &snapshot.TokensOut, &snapshot.CostUSD,
		&policiesChecked, &policiesTriggered,
		&errorMessage, &snapshot.RetryCount, &snapshot.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot: %w", err)
	}

	snapshot.Status = StepStatus(status)
	if completedAt.Valid {
		snapshot.CompletedAt = &completedAt.Time
	}
	if durationMs.Valid {
		d := int(durationMs.Int32)
		snapshot.DurationMs = &d
	}
	if provider.Valid {
		snapshot.Provider = provider.String
	}
	if model.Valid {
		snapshot.Model = model.String
	}
	if errorMessage.Valid {
		snapshot.ErrorMessage = errorMessage.String
	}

	if err := json.Unmarshal(policiesChecked, &snapshot.PoliciesChecked); err != nil {
		snapshot.PoliciesChecked = []string{}
	}
	if err := json.Unmarshal(policiesTriggered, &snapshot.PoliciesTriggered); err != nil {
		snapshot.PoliciesTriggered = []PolicyEvent{}
	}

	return snapshot, nil
}

// GetSnapshots retrieves all snapshots for an execution
func (r *PostgresRepository) GetSnapshots(ctx context.Context, requestID string) ([]ExecutionSnapshot, error) {
	query := `
		SELECT id, request_id, step_index, step_name, status,
			started_at, completed_at, duration_ms,
			input, output,
			provider, model, tokens_in, tokens_out, cost_usd,
			policies_checked, policies_triggered,
			error_message, retry_count, created_at
		FROM execution_snapshots
		WHERE request_id = $1
		ORDER BY step_index ASC`

	rows, err := r.db.QueryContext(ctx, query, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshots: %w", err)
	}
	defer rows.Close()

	var snapshots []ExecutionSnapshot
	for rows.Next() {
		var snapshot ExecutionSnapshot
		var status string
		var policiesChecked, policiesTriggered []byte
		var completedAt sql.NullTime
		var durationMs sql.NullInt32
		var provider, model, errorMessage sql.NullString

		err := rows.Scan(
			&snapshot.ID, &snapshot.RequestID, &snapshot.StepIndex, &snapshot.StepName, &status,
			&snapshot.StartedAt, &completedAt, &durationMs,
			&snapshot.Input, &snapshot.Output,
			&provider, &model, &snapshot.TokensIn, &snapshot.TokensOut, &snapshot.CostUSD,
			&policiesChecked, &policiesTriggered,
			&errorMessage, &snapshot.RetryCount, &snapshot.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan snapshot: %w", err)
		}

		snapshot.Status = StepStatus(status)
		if completedAt.Valid {
			snapshot.CompletedAt = &completedAt.Time
		}
		if durationMs.Valid {
			d := int(durationMs.Int32)
			snapshot.DurationMs = &d
		}
		if provider.Valid {
			snapshot.Provider = provider.String
		}
		if model.Valid {
			snapshot.Model = model.String
		}
		if errorMessage.Valid {
			snapshot.ErrorMessage = errorMessage.String
		}

		if err := json.Unmarshal(policiesChecked, &snapshot.PoliciesChecked); err != nil {
			snapshot.PoliciesChecked = []string{}
		}
		if err := json.Unmarshal(policiesTriggered, &snapshot.PoliciesTriggered); err != nil {
			snapshot.PoliciesTriggered = []PolicyEvent{}
		}

		snapshots = append(snapshots, snapshot)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating snapshots: %w", err)
	}

	return snapshots, nil
}

// DeleteSnapshots removes all snapshots for an execution
func (r *PostgresRepository) DeleteSnapshots(ctx context.Context, requestID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM execution_snapshots WHERE request_id = $1", requestID)
	if err != nil {
		return fmt.Errorf("failed to delete snapshots: %w", err)
	}
	return nil
}

// emptyJSON is used as a default for nil json.RawMessage to satisfy PostgreSQL jsonb columns
var emptyJSON = json.RawMessage("{}")

// toValidJSON returns a valid JSON value, using emptyJSON for nil or empty values
func toValidJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return emptyJSON
	}
	return raw
}

// SaveSummary saves an execution summary
func (r *PostgresRepository) SaveSummary(ctx context.Context, summary *ExecutionSummary) error {
	if summary == nil {
		return ErrInvalidInput
	}

	query := `
		INSERT INTO execution_summaries (
			request_id, workflow_name, status, total_steps, completed_steps,
			started_at, completed_at, duration_ms,
			total_tokens, total_cost_usd,
			org_id, tenant_id, user_id, agent_id,
			input_summary, output_summary, error_message
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10,
			$11, $12, $13, $14,
			$15, $16, $17
		)
		ON CONFLICT (request_id) DO UPDATE SET
			status = EXCLUDED.status,
			completed_steps = EXCLUDED.completed_steps,
			completed_at = EXCLUDED.completed_at,
			duration_ms = EXCLUDED.duration_ms,
			total_tokens = EXCLUDED.total_tokens,
			total_cost_usd = EXCLUDED.total_cost_usd,
			output_summary = EXCLUDED.output_summary,
			error_message = EXCLUDED.error_message`

	_, err := r.db.ExecContext(ctx, query,
		summary.RequestID, summary.WorkflowName, string(summary.Status), summary.TotalSteps, summary.CompletedSteps,
		summary.StartedAt, summary.CompletedAt, summary.DurationMs,
		summary.TotalTokens, summary.TotalCostUSD,
		summary.OrgID, summary.TenantID, summary.UserID, summary.AgentID,
		toValidJSON(summary.InputSummary), toValidJSON(summary.OutputSummary), summary.ErrorMessage,
	)

	if err != nil {
		return fmt.Errorf("failed to save summary: %w", err)
	}

	return nil
}

// UpdateSummary updates an existing summary
func (r *PostgresRepository) UpdateSummary(ctx context.Context, summary *ExecutionSummary) error {
	return r.SaveSummary(ctx, summary) // Upsert handles updates
}

// GetSummary retrieves an execution summary by request ID
func (r *PostgresRepository) GetSummary(ctx context.Context, requestID string) (*ExecutionSummary, error) {
	query := `
		SELECT request_id, workflow_name, status, total_steps, completed_steps,
			started_at, completed_at, duration_ms,
			total_tokens, total_cost_usd,
			org_id, tenant_id, user_id, agent_id,
			input_summary, output_summary, error_message,
			created_at, updated_at
		FROM execution_summaries
		WHERE request_id = $1`

	summary := &ExecutionSummary{}
	var status string
	var completedAt sql.NullTime
	var durationMs sql.NullInt32
	var workflowName, orgID, tenantID, userID, agentID, errorMessage sql.NullString

	err := r.db.QueryRowContext(ctx, query, requestID).Scan(
		&summary.RequestID, &workflowName, &status, &summary.TotalSteps, &summary.CompletedSteps,
		&summary.StartedAt, &completedAt, &durationMs,
		&summary.TotalTokens, &summary.TotalCostUSD,
		&orgID, &tenantID, &userID, &agentID,
		&summary.InputSummary, &summary.OutputSummary, &errorMessage,
		&summary.CreatedAt, &summary.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get summary: %w", err)
	}

	summary.Status = ExecutionStatus(status)
	if completedAt.Valid {
		summary.CompletedAt = &completedAt.Time
	}
	if durationMs.Valid {
		d := int(durationMs.Int32)
		summary.DurationMs = &d
	}
	if workflowName.Valid {
		summary.WorkflowName = workflowName.String
	}
	if orgID.Valid {
		summary.OrgID = orgID.String
	}
	if tenantID.Valid {
		summary.TenantID = tenantID.String
	}
	if userID.Valid {
		summary.UserID = userID.String
	}
	if agentID.Valid {
		summary.AgentID = agentID.String
	}
	if errorMessage.Valid {
		summary.ErrorMessage = errorMessage.String
	}

	return summary, nil
}

// ListSummaries retrieves execution summaries with filtering and pagination
func (r *PostgresRepository) ListSummaries(ctx context.Context, opts ListOptions) ([]ExecutionSummary, int, error) {
	// Build dynamic query based on options
	var conditions []string
	var args []interface{}
	argIndex := 1

	if opts.OrgID != "" {
		conditions = append(conditions, fmt.Sprintf("org_id = $%d", argIndex))
		args = append(args, opts.OrgID)
		argIndex++
	}
	if opts.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, opts.TenantID)
		argIndex++
	}
	if opts.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, opts.Status)
		argIndex++
	}
	if opts.WorkflowID != "" {
		conditions = append(conditions, fmt.Sprintf("workflow_name = $%d", argIndex))
		args = append(args, opts.WorkflowID)
		argIndex++
	}
	if opts.StartTime != nil {
		conditions = append(conditions, fmt.Sprintf("started_at >= $%d", argIndex))
		args = append(args, *opts.StartTime)
		argIndex++
	}
	if opts.EndTime != nil {
		conditions = append(conditions, fmt.Sprintf("started_at <= $%d", argIndex))
		args = append(args, *opts.EndTime)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM execution_summaries %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count summaries: %w", err)
	}

	// Set defaults
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 1000 {
		opts.Limit = 1000
	}

	// Get summaries with pagination
	query := fmt.Sprintf(`
		SELECT request_id, workflow_name, status, total_steps, completed_steps,
			started_at, completed_at, duration_ms,
			total_tokens, total_cost_usd,
			org_id, tenant_id, user_id, agent_id,
			input_summary, output_summary, error_message,
			created_at, updated_at
		FROM execution_summaries
		%s
		ORDER BY started_at DESC
		LIMIT $%d OFFSET $%d`,
		whereClause, argIndex, argIndex+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list summaries: %w", err)
	}
	defer rows.Close()

	var summaries []ExecutionSummary
	for rows.Next() {
		var summary ExecutionSummary
		var status string
		var completedAt sql.NullTime
		var durationMs sql.NullInt32
		var workflowName, orgID, tenantID, userID, agentID, errorMessage sql.NullString

		err := rows.Scan(
			&summary.RequestID, &workflowName, &status, &summary.TotalSteps, &summary.CompletedSteps,
			&summary.StartedAt, &completedAt, &durationMs,
			&summary.TotalTokens, &summary.TotalCostUSD,
			&orgID, &tenantID, &userID, &agentID,
			&summary.InputSummary, &summary.OutputSummary, &errorMessage,
			&summary.CreatedAt, &summary.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan summary: %w", err)
		}

		summary.Status = ExecutionStatus(status)
		if completedAt.Valid {
			summary.CompletedAt = &completedAt.Time
		}
		if durationMs.Valid {
			d := int(durationMs.Int32)
			summary.DurationMs = &d
		}
		if workflowName.Valid {
			summary.WorkflowName = workflowName.String
		}
		if orgID.Valid {
			summary.OrgID = orgID.String
		}
		if tenantID.Valid {
			summary.TenantID = tenantID.String
		}
		if userID.Valid {
			summary.UserID = userID.String
		}
		if agentID.Valid {
			summary.AgentID = agentID.String
		}
		if errorMessage.Valid {
			summary.ErrorMessage = errorMessage.String
		}

		summaries = append(summaries, summary)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating summaries: %w", err)
	}

	return summaries, total, nil
}

// DeleteSummary removes an execution summary
func (r *PostgresRepository) DeleteSummary(ctx context.Context, requestID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM execution_summaries WHERE request_id = $1", requestID)
	if err != nil {
		return fmt.Errorf("failed to delete summary: %w", err)
	}
	return nil
}

// GetExecution retrieves a full execution with summary and all steps
func (r *PostgresRepository) GetExecution(ctx context.Context, requestID string) (*Execution, error) {
	summary, err := r.GetSummary(ctx, requestID)
	if err != nil {
		return nil, err
	}

	steps, err := r.GetSnapshots(ctx, requestID)
	if err != nil {
		return nil, err
	}

	return &Execution{
		Summary: summary,
		Steps:   steps,
	}, nil
}

// DeleteExecution removes an execution and all its snapshots
func (r *PostgresRepository) DeleteExecution(ctx context.Context, requestID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete snapshots first (child records)
	if _, err := tx.ExecContext(ctx, "DELETE FROM execution_snapshots WHERE request_id = $1", requestID); err != nil {
		return fmt.Errorf("failed to delete snapshots: %w", err)
	}

	// Delete summary
	if _, err := tx.ExecContext(ctx, "DELETE FROM execution_summaries WHERE request_id = $1", requestID); err != nil {
		return fmt.Errorf("failed to delete summary: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Ping checks the database connection
func (r *PostgresRepository) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.db.PingContext(ctx)
}
