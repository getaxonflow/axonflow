// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Repository defines the interface for workflow persistence
type Repository interface {
	// Workflow operations
	Create(ctx context.Context, workflow *Workflow) error
	Delete(ctx context.Context, workflowID string) error
	GetByID(ctx context.Context, workflowID string) (*Workflow, error)
	UpdateStatus(ctx context.Context, workflowID string, status WorkflowStatus) error
	Complete(ctx context.Context, workflowID string) error
	Abort(ctx context.Context, workflowID string, reason string) error
	Fail(ctx context.Context, workflowID string, reason string) error
	List(ctx context.Context, opts ListWorkflowsOptions) ([]Workflow, int, error)

	// Step operations
	AddStep(ctx context.Context, step *WorkflowStep) error
	GetStep(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error)
	UpdateStepApproval(ctx context.Context, workflowID, stepID string, status ApprovalStatus, approvedBy string) error
	MarkStepCompleted(ctx context.Context, workflowID, stepID string, req *StepCompleteRequest) error
	GetStepsForWorkflow(ctx context.Context, workflowID string) ([]WorkflowStep, error)
	GetPendingApprovals(ctx context.Context, tenantID string, limit int) ([]WorkflowStep, error)
}

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// Create inserts a new workflow
func (r *PostgresRepository) Create(ctx context.Context, workflow *Workflow) error {
	if workflow.WorkflowID == "" {
		workflow.WorkflowID = fmt.Sprintf("wf_%s", uuid.New().String()[:8])
	}

	if workflow.Source == "" {
		workflow.Source = WorkflowSourceExternal
	}

	if workflow.Status == "" {
		workflow.Status = WorkflowStatusInProgress
	}

	now := time.Now()
	workflow.StartedAt = now
	workflow.CreatedAt = now
	workflow.UpdatedAt = now

	metadata := workflow.Metadata
	if metadata == nil {
		metadata = json.RawMessage("{}")
	}

	query := `
		INSERT INTO workflows (
			workflow_id, workflow_name, source, status,
			current_step_index, total_steps,
			org_id, tenant_id, user_id, client_id,
			metadata, started_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err := r.db.ExecContext(ctx, query,
		workflow.WorkflowID,
		workflow.WorkflowName,
		workflow.Source,
		workflow.Status,
		workflow.CurrentStepIndex,
		workflow.TotalSteps,
		workflow.OrgID,
		workflow.TenantID,
		workflow.UserID,
		workflow.ClientID,
		metadata,
		workflow.StartedAt,
		workflow.CreatedAt,
		workflow.UpdatedAt,
	)

	return err
}

// Delete removes a workflow record by ID.
func (r *PostgresRepository) Delete(ctx context.Context, workflowID string) error {
	query := `DELETE FROM workflows WHERE workflow_id = $1`
	_, err := r.db.ExecContext(ctx, query, workflowID)
	return err
}

// GetByID retrieves a workflow by ID including its steps
func (r *PostgresRepository) GetByID(ctx context.Context, workflowID string) (*Workflow, error) {
	query := `
		SELECT workflow_id, workflow_name, source, status,
			   current_step_index, total_steps,
			   org_id, tenant_id, user_id, client_id,
			   metadata, started_at, completed_at, created_at, updated_at
		FROM workflows
		WHERE workflow_id = $1
	`

	var workflow Workflow
	var totalSteps sql.NullInt64
	var completedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, workflowID).Scan(
		&workflow.WorkflowID,
		&workflow.WorkflowName,
		&workflow.Source,
		&workflow.Status,
		&workflow.CurrentStepIndex,
		&totalSteps,
		&workflow.OrgID,
		&workflow.TenantID,
		&workflow.UserID,
		&workflow.ClientID,
		&workflow.Metadata,
		&workflow.StartedAt,
		&completedAt,
		&workflow.CreatedAt,
		&workflow.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}
	if err != nil {
		return nil, err
	}

	if totalSteps.Valid {
		ts := int(totalSteps.Int64)
		workflow.TotalSteps = &ts
	}
	if completedAt.Valid {
		workflow.CompletedAt = &completedAt.Time
	}

	// Fetch steps
	steps, err := r.GetStepsForWorkflow(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	workflow.Steps = steps

	return &workflow, nil
}

// UpdateStatus updates a workflow's status
func (r *PostgresRepository) UpdateStatus(ctx context.Context, workflowID string, status WorkflowStatus) error {
	query := `UPDATE workflows SET status = $1, updated_at = $2 WHERE workflow_id = $3`
	result, err := r.db.ExecContext(ctx, query, status, time.Now(), workflowID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	return nil
}

// Complete marks a workflow as completed.
// If total_steps was not declared upfront (open-ended workflow), it is finalised to
// current_step_index so historical queries have an accurate step count.
func (r *PostgresRepository) Complete(ctx context.Context, workflowID string) error {
	now := time.Now()
	query := `
		UPDATE workflows
		SET status = $1, completed_at = $2, updated_at = $3,
		    total_steps = COALESCE(total_steps, current_step_index)
		WHERE workflow_id = $4`
	result, err := r.db.ExecContext(ctx, query, WorkflowStatusCompleted, now, now, workflowID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	return nil
}

// Abort marks a workflow as aborted with reason.
// If total_steps was not declared upfront, it is finalised to current_step_index.
func (r *PostgresRepository) Abort(ctx context.Context, workflowID string, reason string) error {
	now := time.Now()
	// Store abort reason in metadata
	query := `
		UPDATE workflows
		SET status = $1,
			completed_at = $2,
			updated_at = $3,
			metadata = metadata || $4::jsonb,
			total_steps = COALESCE(total_steps, current_step_index)
		WHERE workflow_id = $5
	`
	reasonJSON, jsonErr := json.Marshal(map[string]string{"abort_reason": reason})
	if jsonErr != nil {
		return fmt.Errorf("marshal abort reason: %w", jsonErr)
	}
	result, err := r.db.ExecContext(ctx, query, WorkflowStatusAborted, now, now, string(reasonJSON), workflowID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	return nil
}

// Fail marks a workflow as failed with reason.
// If total_steps was not declared upfront, it is finalised to current_step_index.
func (r *PostgresRepository) Fail(ctx context.Context, workflowID string, reason string) error {
	now := time.Now()
	query := `
		UPDATE workflows
		SET status = $1,
			completed_at = $2,
			updated_at = $3,
			metadata = metadata || $4::jsonb,
			total_steps = COALESCE(total_steps, current_step_index)
		WHERE workflow_id = $5
	`
	reasonJSON, jsonErr := json.Marshal(map[string]string{"failure_reason": reason})
	if jsonErr != nil {
		return fmt.Errorf("marshal failure reason: %w", jsonErr)
	}
	result, err := r.db.ExecContext(ctx, query, WorkflowStatusFailed, now, now, string(reasonJSON), workflowID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	return nil
}

// List retrieves workflows with optional filters
func (r *PostgresRepository) List(ctx context.Context, opts ListWorkflowsOptions) ([]Workflow, int, error) {
	// Build query with filters
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argNum))
		args = append(args, opts.TenantID)
		argNum++
	}

	if opts.OrgID != "" {
		conditions = append(conditions, fmt.Sprintf("org_id = $%d", argNum))
		args = append(args, opts.OrgID)
		argNum++
	}

	if opts.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argNum))
		args = append(args, *opts.Status)
		argNum++
	}

	if opts.Source != nil {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argNum))
		args = append(args, *opts.Source)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM workflows %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Get workflows with pagination
	limit := opts.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	query := fmt.Sprintf(`
		SELECT workflow_id, workflow_name, source, status,
			   current_step_index, total_steps,
			   org_id, tenant_id, user_id, client_id,
			   metadata, started_at, completed_at, created_at, updated_at
		FROM workflows
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argNum, argNum+1)

	args = append(args, limit, opts.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var workflows []Workflow
	for rows.Next() {
		var workflow Workflow
		var totalSteps sql.NullInt64
		var completedAt sql.NullTime

		err := rows.Scan(
			&workflow.WorkflowID,
			&workflow.WorkflowName,
			&workflow.Source,
			&workflow.Status,
			&workflow.CurrentStepIndex,
			&totalSteps,
			&workflow.OrgID,
			&workflow.TenantID,
			&workflow.UserID,
			&workflow.ClientID,
			&workflow.Metadata,
			&workflow.StartedAt,
			&completedAt,
			&workflow.CreatedAt,
			&workflow.UpdatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

		if totalSteps.Valid {
			ts := int(totalSteps.Int64)
			workflow.TotalSteps = &ts
		}
		if completedAt.Valid {
			workflow.CompletedAt = &completedAt.Time
		}

		steps, err := r.GetStepsForWorkflow(ctx, workflow.WorkflowID)
		if err != nil {
			return nil, 0, err
		}
		workflow.Steps = steps

		workflows = append(workflows, workflow)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate workflow rows: %w", err)
	}

	return workflows, total, nil
}

// AddStep records a new step gate decision
func (r *PostgresRepository) AddStep(ctx context.Context, step *WorkflowStep) error {
	now := time.Now()
	step.GateCheckedAt = now

	policiesEvaluated := step.PoliciesEvaluated
	if policiesEvaluated == nil {
		policiesEvaluated = json.RawMessage("[]")
	}
	policiesMatched := step.PoliciesMatched
	if policiesMatched == nil {
		policiesMatched = json.RawMessage("[]")
	}
	stepInput := step.StepInput
	if stepInput == nil {
		stepInput = json.RawMessage("{}")
	}

	query := `
		INSERT INTO workflow_steps (
			workflow_id, step_id, step_index, step_name, step_type,
			decision, decision_reason, policies_evaluated, policies_matched,
			approval_status, step_input, model, provider,
			tokens_in, tokens_out, cost_usd, gate_checked_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (workflow_id, step_id) DO UPDATE SET
			decision = EXCLUDED.decision,
			decision_reason = EXCLUDED.decision_reason,
			policies_evaluated = EXCLUDED.policies_evaluated,
			policies_matched = EXCLUDED.policies_matched,
			approval_status = EXCLUDED.approval_status,
			tokens_in = EXCLUDED.tokens_in,
			tokens_out = EXCLUDED.tokens_out,
			cost_usd = EXCLUDED.cost_usd,
			gate_checked_at = EXCLUDED.gate_checked_at
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		step.WorkflowID,
		step.StepID,
		step.StepIndex,
		step.StepName,
		step.StepType,
		step.Decision,
		step.DecisionReason,
		policiesEvaluated,
		policiesMatched,
		step.ApprovalStatus,
		stepInput,
		step.Model,
		step.Provider,
		step.TokensIn,
		step.TokensOut,
		step.CostUSD,
		step.GateCheckedAt,
	).Scan(&step.ID)

	if err != nil {
		return err
	}

	// Update workflow's current step index
	updateQuery := `
		UPDATE workflows
		SET current_step_index = $1, updated_at = $2
		WHERE workflow_id = $3 AND current_step_index < $1
	`
	_, _ = r.db.ExecContext(ctx, updateQuery, step.StepIndex, now, step.WorkflowID)

	return nil
}

// GetStep retrieves a specific step
func (r *PostgresRepository) GetStep(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	query := `
		SELECT id, workflow_id, step_id, step_index, step_name, step_type,
			   decision, decision_reason, policies_evaluated, policies_matched,
			   approval_status, approved_by, approved_at,
			   step_input, model, provider, tokens_in, tokens_out, cost_usd,
			   step_output, gate_checked_at, step_completed_at
		FROM workflow_steps
		WHERE workflow_id = $1 AND step_id = $2
	`

	var step WorkflowStep
	var approvalStatus sql.NullString
	var approvedBy sql.NullString
	var approvedAt sql.NullTime
	var stepCompletedAt sql.NullTime
	var stepOutput []byte

	err := r.db.QueryRowContext(ctx, query, workflowID, stepID).Scan(
		&step.ID,
		&step.WorkflowID,
		&step.StepID,
		&step.StepIndex,
		&step.StepName,
		&step.StepType,
		&step.Decision,
		&step.DecisionReason,
		&step.PoliciesEvaluated,
		&step.PoliciesMatched,
		&approvalStatus,
		&approvedBy,
		&approvedAt,
		&step.StepInput,
		&step.Model,
		&step.Provider,
		&step.TokensIn,
		&step.TokensOut,
		&step.CostUSD,
		&stepOutput,
		&step.GateCheckedAt,
		&stepCompletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("step not found: %s/%s", workflowID, stepID)
	}
	if err != nil {
		return nil, err
	}

	if approvalStatus.Valid {
		as := ApprovalStatus(approvalStatus.String)
		step.ApprovalStatus = &as
	}
	if approvedBy.Valid {
		step.ApprovedBy = approvedBy.String
	}
	if approvedAt.Valid {
		step.ApprovedAt = &approvedAt.Time
	}
	if stepCompletedAt.Valid {
		step.StepCompletedAt = &stepCompletedAt.Time
	}
	if stepOutput != nil {
		step.StepOutput = json.RawMessage(stepOutput)
	}

	return &step, nil
}

// UpdateStepApproval updates the approval status of a step
func (r *PostgresRepository) UpdateStepApproval(ctx context.Context, workflowID, stepID string, status ApprovalStatus, approvedBy string) error {
	now := time.Now()
	query := `
		UPDATE workflow_steps
		SET approval_status = $1, approved_by = $2, approved_at = $3
		WHERE workflow_id = $4 AND step_id = $5
	`
	result, err := r.db.ExecContext(ctx, query, status, approvedBy, now, workflowID, stepID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("step not found: %s/%s", workflowID, stepID)
	}

	return nil
}

// MarkStepCompleted marks a step as completed, optionally updating post-execution metrics.
func (r *PostgresRepository) MarkStepCompleted(ctx context.Context, workflowID, stepID string, req *StepCompleteRequest) error {
	now := time.Now()

	// Extract optional metrics from request
	var tokensIn, tokensOut *int
	var costUSD *float64
	var stepOutput interface{} // use interface{} so nil maps to SQL NULL
	if req != nil {
		tokensIn = req.TokensIn
		tokensOut = req.TokensOut
		costUSD = req.CostUSD
		if req.Output != nil {
			data, err := json.Marshal(req.Output)
			if err != nil {
				return fmt.Errorf("marshal step output: %w", err)
			}
			stepOutput = json.RawMessage(data)
		}
	}

	query := `
		UPDATE workflow_steps
		SET step_completed_at = $1,
		    tokens_in = COALESCE($4, tokens_in),
		    tokens_out = COALESCE($5, tokens_out),
		    cost_usd = COALESCE($6, cost_usd),
		    step_output = COALESCE($7, step_output)
		WHERE workflow_id = $2 AND step_id = $3
	`
	result, err := r.db.ExecContext(ctx, query, now, workflowID, stepID, tokensIn, tokensOut, costUSD, stepOutput)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("step not found: %s/%s", workflowID, stepID)
	}

	return nil
}

// GetStepsForWorkflow retrieves all steps for a workflow
func (r *PostgresRepository) GetStepsForWorkflow(ctx context.Context, workflowID string) ([]WorkflowStep, error) {
	query := `
		SELECT id, workflow_id, step_id, step_index, step_name, step_type,
			   decision, decision_reason, policies_evaluated, policies_matched,
			   approval_status, approved_by, approved_at,
			   step_input, model, provider, tokens_in, tokens_out, cost_usd,
			   step_output, gate_checked_at, step_completed_at
		FROM workflow_steps
		WHERE workflow_id = $1
		ORDER BY step_index ASC
	`

	rows, err := r.db.QueryContext(ctx, query, workflowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var steps []WorkflowStep
	for rows.Next() {
		var step WorkflowStep
		var approvalStatus sql.NullString
		var approvedBy sql.NullString
		var approvedAt sql.NullTime
		var stepCompletedAt sql.NullTime
		var stepOutput []byte

		err := rows.Scan(
			&step.ID,
			&step.WorkflowID,
			&step.StepID,
			&step.StepIndex,
			&step.StepName,
			&step.StepType,
			&step.Decision,
			&step.DecisionReason,
			&step.PoliciesEvaluated,
			&step.PoliciesMatched,
			&approvalStatus,
			&approvedBy,
			&approvedAt,
			&step.StepInput,
			&step.Model,
			&step.Provider,
			&step.TokensIn,
			&step.TokensOut,
			&step.CostUSD,
			&stepOutput,
			&step.GateCheckedAt,
			&stepCompletedAt,
		)
		if err != nil {
			return nil, err
		}

		if approvalStatus.Valid {
			as := ApprovalStatus(approvalStatus.String)
			step.ApprovalStatus = &as
		}
		if approvedBy.Valid {
			step.ApprovedBy = approvedBy.String
		}
		if approvedAt.Valid {
			step.ApprovedAt = &approvedAt.Time
		}
		if stepCompletedAt.Valid {
			step.StepCompletedAt = &stepCompletedAt.Time
		}
		if stepOutput != nil {
			step.StepOutput = json.RawMessage(stepOutput)
		}

		steps = append(steps, step)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate step rows: %w", err)
	}

	return steps, nil
}

// GetPendingApprovals retrieves steps awaiting approval for a tenant
func (r *PostgresRepository) GetPendingApprovals(ctx context.Context, tenantID string, limit int) ([]WorkflowStep, error) {
	if limit <= 0 {
		limit = 20
	}

	query := `
		SELECT ws.id, ws.workflow_id, ws.step_id, ws.step_index, ws.step_name, ws.step_type,
			   ws.decision, ws.decision_reason, ws.policies_evaluated, ws.policies_matched,
			   ws.approval_status, ws.step_input, ws.model, ws.provider,
			   ws.tokens_in, ws.tokens_out, ws.gate_checked_at
		FROM workflow_steps ws
		JOIN workflows w ON ws.workflow_id = w.workflow_id
		WHERE ws.approval_status = 'pending' AND w.tenant_id = $1
		ORDER BY ws.gate_checked_at DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var steps []WorkflowStep
	for rows.Next() {
		var step WorkflowStep
		var approvalStatus sql.NullString

		err := rows.Scan(
			&step.ID,
			&step.WorkflowID,
			&step.StepID,
			&step.StepIndex,
			&step.StepName,
			&step.StepType,
			&step.Decision,
			&step.DecisionReason,
			&step.PoliciesEvaluated,
			&step.PoliciesMatched,
			&approvalStatus,
			&step.StepInput,
			&step.Model,
			&step.Provider,
			&step.TokensIn,
			&step.TokensOut,
			&step.GateCheckedAt,
		)
		if err != nil {
			return nil, err
		}

		if approvalStatus.Valid {
			as := ApprovalStatus(approvalStatus.String)
			step.ApprovalStatus = &as
		}

		steps = append(steps, step)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending approval rows: %w", err)
	}

	return steps, nil
}
