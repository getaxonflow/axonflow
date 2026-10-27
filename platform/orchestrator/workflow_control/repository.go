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

	"axonflow/platform/agent/rls"
	"axonflow/platform/shared/tenantscope"
)

// Repository defines the interface for workflow persistence
type Repository interface {
	// Workflow operations
	Create(ctx context.Context, workflow *Workflow) error
	Delete(ctx context.Context, workflowID string) error
	GetByID(ctx context.Context, workflowID string) (*Workflow, error)
	// GetByPlanID looks up a WCP workflow by MAP plan id (metadata->>'plan_id').
	// MAP's plan-level HITL endpoints use this to surface rich step-gate state
	// on the plan-scoped /approve and /reject paths (Issue #1677 Phase 1).
	// Returns "workflow not found" style error when no workflow matches.
	GetByPlanID(ctx context.Context, planID string) (*Workflow, error)
	UpdateStatus(ctx context.Context, workflowID string, status WorkflowStatus) error
	Complete(ctx context.Context, workflowID string) error
	Abort(ctx context.Context, workflowID string, reason string) error
	Fail(ctx context.Context, workflowID string, reason string) error
	List(ctx context.Context, opts ListWorkflowsOptions) ([]Workflow, int, error)

	// Step operations
	AddStep(ctx context.Context, step *WorkflowStep) error
	// InsertStepRunRecord writes step as a NEW row and never touches an
	// existing one: inserted is false when the step already has a row
	// (Service.RecordStepRun, #4249 row 5701284807).
	InsertStepRunRecord(ctx context.Context, step *WorkflowStep) (inserted bool, err error)
	GetStep(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error)
	// GetStepDecision retrieves a step's cached decision for idempotent retry support (#1414).
	// Returns nil (not error) if the step has not been evaluated yet.
	GetStepDecision(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error)
	// BumpGateCountCached is called by the cached-hit path of StepGate to
	// increment gate_count and snapshot last_decision without changing the
	// stored decision (Issue #1673 Phase 1). Returns the updated row.
	BumpGateCountCached(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error)
	UpdateStepApproval(ctx context.Context, workflowID, stepID string, status ApprovalStatus, approvedBy string, comment string) error
	MarkStepCompleted(ctx context.Context, workflowID, stepID string, req *StepCompleteRequest) error
	GetStepsForWorkflow(ctx context.Context, workflowID string) ([]WorkflowStep, error)
	GetPendingApprovals(ctx context.Context, tenantID string, limit int) ([]PendingApprovalResponse, error)
	CountPendingApprovals(ctx context.Context, tenantID string) (int, error)
	// GetPendingPlanApprovals returns steps awaiting approval for MAP-backed
	// workflows only (workflows.metadata->>'plan_id' IS NOT NULL). Each entry
	// has PlanID populated from the metadata. Optionally filter to a specific
	// plan via planIDFilter — empty string means all MAP-backed plans.
	// Issue #1680: the MAP-plane equivalent of GetPendingApprovals.
	GetPendingPlanApprovals(ctx context.Context, tenantID, planIDFilter string, limit int) ([]PendingApprovalResponse, error)
	// CountPendingPlanApprovals counts MAP-backed pending approvals for a tenant,
	// optionally scoped to a specific plan_id. See GetPendingPlanApprovals.
	CountPendingPlanApprovals(ctx context.Context, tenantID, planIDFilter string) (int, error)

	// Checkpoint operations — step-gate checkpoints for safe resume
	CreateCheckpoint(ctx context.Context, cp *Checkpoint) error
	ListCheckpoints(ctx context.Context, workflowID string) ([]Checkpoint, error)
	GetLastResumableCheckpoint(ctx context.Context, workflowID string) (*Checkpoint, error)
	GetCheckpointByID(ctx context.Context, id int64) (*Checkpoint, error)
	IncrementResumeCount(ctx context.Context, id int64) error
}

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	db      *sql.DB
	adminDB *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// SetAdminDB wires the BYPASSRLS pool used by explicitly named reconciliation
// reads. Request handlers continue to use the tenant-scoped methods.
func (r *PostgresRepository) SetAdminDB(db *sql.DB) { r.adminDB = db }

func workflowOrgScope(ctx context.Context) (string, error) {
	s, err := tenantscope.FromContext(ctx)
	if err != nil {
		return "", ErrWorkflowNotFound
	}
	return s.OrgID, nil
}

func (r *PostgresRepository) execScoped(ctx context.Context, query string, args ...interface{}) (result sql.Result, err error) {
	orgID, err := workflowOrgScope(ctx)
	if err != nil {
		return nil, err
	}
	err = rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx, query, args...)
		return execErr
	})
	return result, err
}

func (r *PostgresRepository) queryRowScoped(ctx context.Context, query string, args []interface{}, dest ...interface{}) error {
	orgID, err := workflowOrgScope(ctx)
	if err != nil {
		return err
	}
	return rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, args...).Scan(dest...)
	})
}

func (r *PostgresRepository) queryScoped(ctx context.Context, query string, args []interface{}, consume func(*sql.Rows) error) error {
	orgID, err := workflowOrgScope(ctx)
	if err != nil {
		return err
	}
	return rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		return consume(rows)
	})
}

type workflowScopedRow struct {
	repo  *PostgresRepository
	ctx   context.Context
	query string
	args  []interface{}
}

func (r workflowScopedRow) Scan(dest ...interface{}) error {
	return r.repo.queryRowScoped(r.ctx, r.query, r.args, dest...)
}
func (r *PostgresRepository) rowScoped(ctx context.Context, query string, args ...interface{}) workflowScopedRow {
	return workflowScopedRow{repo: r, ctx: ctx, query: query, args: args}
}

// Create inserts a new workflow
func (r *PostgresRepository) Create(ctx context.Context, workflow *Workflow) error {
	if workflow == nil {
		return fmt.Errorf("workflow is required")
	}
	if workflow.OrgID == "" || workflow.TenantID == "" {
		if scope, err := tenantscope.FromContext(ctx); err == nil {
			if workflow.OrgID == "" {
				workflow.OrgID = scope.OrgID
			}
			if workflow.TenantID == "" {
				workflow.TenantID = scope.TenantID
			}
		}
	}
	if err := tenantscope.ValidateRowKeys(workflow.OrgID, workflow.TenantID); err != nil {
		return fmt.Errorf("refusing to persist workflow without org/tenant scope: %w", err)
	}
	if workflow.WorkflowID == "" {
		workflow.WorkflowID = NewWorkflowID()
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
			trace_id, metadata, started_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	var traceID sql.NullString
	if workflow.TraceID != "" {
		traceID = sql.NullString{String: workflow.TraceID, Valid: true}
	}

	err := rls.WithOrgScope(ctx, r.db, workflow.OrgID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
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
			traceID,
			metadata,
			workflow.StartedAt,
			workflow.CreatedAt,
			workflow.UpdatedAt,
		)
		return e
	})

	return err
}

// Delete removes a workflow record by ID.
func (r *PostgresRepository) Delete(ctx context.Context, workflowID string) error {
	query := `DELETE FROM workflows WHERE workflow_id = $1`
	orgID, err := workflowOrgScope(ctx)
	if err != nil {
		return err
	}
	err = rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error { _, e := tx.ExecContext(ctx, query, workflowID); return e })
	return err
}

// GetByID retrieves a workflow by ID including its steps
func (r *PostgresRepository) GetByID(ctx context.Context, workflowID string) (*Workflow, error) {
	query := `
		SELECT workflow_id, workflow_name, source, status,
			   current_step_index, total_steps,
			   org_id, tenant_id, user_id, client_id,
			   trace_id, metadata, started_at, completed_at, created_at, updated_at
		FROM workflows
		WHERE workflow_id = $1
	`

	var workflow Workflow
	var totalSteps sql.NullInt64
	var completedAt sql.NullTime
	var traceID sql.NullString

	var wfOrgID, wfTenantID, wfUserID, wfClientID sql.NullString
	orgID, err := workflowOrgScope(ctx)
	if err != nil {
		return nil, err
	}
	err = rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, workflowID).Scan(
			&workflow.WorkflowID,
			&workflow.WorkflowName,
			&workflow.Source,
			&workflow.Status,
			&workflow.CurrentStepIndex,
			&totalSteps,
			&wfOrgID,
			&wfTenantID,
			&wfUserID,
			&wfClientID,
			&traceID,
			&workflow.Metadata,
			&workflow.StartedAt,
			&completedAt,
			&workflow.CreatedAt,
			&workflow.UpdatedAt,
		)
	})

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}
	if err != nil {
		return nil, err
	}

	workflow.OrgID = wfOrgID.String
	workflow.TenantID = wfTenantID.String
	workflow.UserID = wfUserID.String
	workflow.ClientID = wfClientID.String

	if totalSteps.Valid {
		ts := int(totalSteps.Int64)
		workflow.TotalSteps = &ts
	}
	if completedAt.Valid {
		workflow.CompletedAt = &completedAt.Time
	}
	if traceID.Valid {
		workflow.TraceID = traceID.String
	}

	// Fetch steps
	steps, err := r.GetStepsForWorkflow(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	workflow.Steps = steps

	return &workflow, nil
}

// GetByIDUnscoped is reserved for in-process reconciliation whose result is
// authorized before it is returned to a caller. It requires the dedicated
// BYPASSRLS pool and never falls back to the application pool.
func (r *PostgresRepository) GetByIDUnscoped(ctx context.Context, workflowID string) (*Workflow, error) {
	if r.adminDB == nil {
		return nil, fmt.Errorf("unscoped workflow reconciliation requires the platform-admin database pool")
	}
	query := `
		SELECT workflow_id, workflow_name, source, status,
			   current_step_index, total_steps,
			   org_id, tenant_id, user_id, client_id,
			   trace_id, metadata, started_at, completed_at, created_at, updated_at
		FROM workflows WHERE workflow_id = $1`
	var workflow Workflow
	var totalSteps sql.NullInt64
	var completedAt sql.NullTime
	var traceID, orgID, tenantID, userID, clientID sql.NullString
	if err := r.adminDB.QueryRowContext(ctx, query, workflowID).Scan(
		&workflow.WorkflowID, &workflow.WorkflowName, &workflow.Source, &workflow.Status,
		&workflow.CurrentStepIndex, &totalSteps,
		&orgID, &tenantID, &userID, &clientID,
		&traceID, &workflow.Metadata, &workflow.StartedAt, &completedAt,
		&workflow.CreatedAt, &workflow.UpdatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
		}
		return nil, err
	}
	workflow.OrgID, workflow.TenantID = orgID.String, tenantID.String
	workflow.UserID, workflow.ClientID = userID.String, clientID.String
	if totalSteps.Valid {
		v := int(totalSteps.Int64)
		workflow.TotalSteps = &v
	}
	if completedAt.Valid {
		workflow.CompletedAt = &completedAt.Time
	}
	if traceID.Valid {
		workflow.TraceID = traceID.String
	}
	rows, err := r.adminDB.QueryContext(ctx, `SELECT `+stepSelectColumns+` FROM workflow_steps WHERE workflow_id = $1 ORDER BY step_index ASC`, workflowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		step, err := scanWorkflowStepRow(rows)
		if err != nil {
			return nil, err
		}
		workflow.Steps = append(workflow.Steps, *step)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &workflow, nil
}

// GetByPlanID resolves a WCP workflow from a MAP plan id. MAP's confirm / step
// executor stores plan_id in metadata when creating the workflow; this lookup
// reverses that association so the plan-scoped HITL endpoints can surface
// rich step-gate state (Issue #1677).
//
// If multiple workflows carry the same plan_id (shouldn't happen — MAP creates
// one workflow per plan execution mode) the most recent workflow wins, so a
// stale terminal workflow doesn't mask an active one.
func (r *PostgresRepository) GetByPlanID(ctx context.Context, planID string) (*Workflow, error) {
	query := `
		SELECT workflow_id, workflow_name, source, status,
			   current_step_index, total_steps,
			   org_id, tenant_id, user_id, client_id,
			   trace_id, metadata, started_at, completed_at, created_at, updated_at
		FROM workflows
		WHERE metadata->>'plan_id' = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	var workflow Workflow
	var totalSteps sql.NullInt64
	var completedAt sql.NullTime
	var traceID sql.NullString

	var wfOrgID, wfTenantID, wfUserID, wfClientID sql.NullString
	orgID, err := workflowOrgScope(ctx)
	if err != nil {
		return nil, err
	}
	err = rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, planID).Scan(
			&workflow.WorkflowID,
			&workflow.WorkflowName,
			&workflow.Source,
			&workflow.Status,
			&workflow.CurrentStepIndex,
			&totalSteps,
			&wfOrgID,
			&wfTenantID,
			&wfUserID,
			&wfClientID,
			&traceID,
			&workflow.Metadata,
			&workflow.StartedAt,
			&completedAt,
			&workflow.CreatedAt,
			&workflow.UpdatedAt,
		)
	})

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("plan %s: %w", planID, ErrWorkflowNotFound)
	}
	if err != nil {
		return nil, err
	}

	workflow.OrgID = wfOrgID.String
	workflow.TenantID = wfTenantID.String
	workflow.UserID = wfUserID.String
	workflow.ClientID = wfClientID.String

	if totalSteps.Valid {
		ts := int(totalSteps.Int64)
		workflow.TotalSteps = &ts
	}
	if completedAt.Valid {
		workflow.CompletedAt = &completedAt.Time
	}
	if traceID.Valid {
		workflow.TraceID = traceID.String
	}

	steps, err := r.GetStepsForWorkflow(ctx, workflow.WorkflowID)
	if err != nil {
		return nil, err
	}
	workflow.Steps = steps

	return &workflow, nil
}

// UpdateStatus updates a workflow's status
func (r *PostgresRepository) UpdateStatus(ctx context.Context, workflowID string, status WorkflowStatus) error {
	query := `UPDATE workflows SET status = $1, updated_at = $2 WHERE workflow_id = $3`
	result, err := r.execScoped(ctx, query, status, time.Now(), workflowID)
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
	result, err := r.execScoped(ctx, query, WorkflowStatusCompleted, now, now, workflowID)
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
	result, err := r.execScoped(ctx, query, WorkflowStatusAborted, now, now, string(reasonJSON), workflowID)
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
	result, err := r.execScoped(ctx, query, WorkflowStatusFailed, now, now, string(reasonJSON), workflowID)
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
	if err := tenantscope.ValidateRowKeys(opts.OrgID, opts.TenantID); err != nil {
		return nil, 0, fmt.Errorf("cannot list workflows without an authenticated org and tenant: %w", err)
	}

	var conditions []string
	var filterArgs []interface{}
	argNum := 1
	add := func(column string, value interface{}) {
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, argNum))
		filterArgs = append(filterArgs, value)
		argNum++
	}
	add("tenant_id", opts.TenantID)
	add("org_id", opts.OrgID)
	if opts.Status != nil {
		add("status", *opts.Status)
	}
	if opts.Source != nil {
		add("source", *opts.Source)
	}
	if opts.TraceID != "" {
		add("trace_id", opts.TraceID)
	}
	if opts.WorkflowName != "" {
		add("workflow_name", opts.WorkflowName)
	}
	whereClause := "WHERE " + strings.Join(conditions, " AND ")

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
			   trace_id, metadata, started_at, completed_at, created_at, updated_at
		FROM workflows
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argNum, argNum+1)
	queryArgs := append(append([]interface{}{}, filterArgs...), limit, opts.Offset)

	var workflows []Workflow
	var total int
	err := rls.WithOrgScope(ctx, r.db, opts.OrgID, func(tx *sql.Tx) error {
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM workflows %s", whereClause)
		if err := tx.QueryRowContext(ctx, countQuery, filterArgs...).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, query, queryArgs...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var workflow Workflow
			var totalSteps sql.NullInt64
			var completedAt sql.NullTime
			var traceID sql.NullString
			var wfOrgID, wfTenantID, wfUserID, wfClientID sql.NullString
			if err := rows.Scan(
				&workflow.WorkflowID, &workflow.WorkflowName, &workflow.Source, &workflow.Status,
				&workflow.CurrentStepIndex, &totalSteps,
				&wfOrgID, &wfTenantID, &wfUserID, &wfClientID,
				&traceID, &workflow.Metadata, &workflow.StartedAt, &completedAt,
				&workflow.CreatedAt, &workflow.UpdatedAt,
			); err != nil {
				return err
			}
			workflow.OrgID = wfOrgID.String
			workflow.TenantID = wfTenantID.String
			workflow.UserID = wfUserID.String
			workflow.ClientID = wfClientID.String
			if totalSteps.Valid {
				v := int(totalSteps.Int64)
				workflow.TotalSteps = &v
			}
			if completedAt.Valid {
				workflow.CompletedAt = &completedAt.Time
			}
			if traceID.Valid {
				workflow.TraceID = traceID.String
			}
			workflows = append(workflows, workflow)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}

	// Load steps after the listing transaction closes. Each read establishes
	// the same transaction-local RLS scope through GetStepsForWorkflow.
	for i := range workflows {
		steps, err := r.GetStepsForWorkflow(ctx, workflows[i].WorkflowID)
		if err != nil {
			return nil, 0, err
		}
		workflows[i].Steps = steps
	}
	return workflows, total, nil
}

// upsertKeepsHold is AddStep's ON CONFLICT condition under which the existing
// row keeps its hold and every field of the evaluation that made it (#4249):
// the row holds rejected or expired (whatever the write carries), or pending
// against a write that is not itself a pending hold. Every SET expression reads
// the row as it was before the statement. Each operand is COALESCEd, so the
// condition is never NULL: a NULL would fall through every CASE to its ELSE.
const upsertKeepsHold = `(COALESCE(workflow_steps.approval_status, '') IN ('rejected', 'expired') OR (COALESCE(workflow_steps.approval_status, '') = 'pending' AND COALESCE(EXCLUDED.approval_status, '') <> 'pending'))`

// upsertLandsNewHold is AddStep's ON CONFLICT condition under which the write
// lands a new pending hold, so the previous decision's approver is cleared.
const upsertLandsNewHold = `(NOT ` + upsertKeepsHold + ` AND COALESCE(EXCLUDED.approval_status, '') = 'pending')`

// AddStep records a new step gate decision and atomically maintains the
// retry_context counters (Issue #1673 Phase 1).
//
// On fresh insert: gate_count = 1, completion_count = 0, last_decision = decision
// (first-call invariant), first_attempt_at = now, idempotency_key = caller value
// or NULL.
//
// On ON CONFLICT (a re-gate on an existing step, usually when retry_policy =
// reevaluate): gate_count = existing + 1, last_decision = existing.decision
// (snapshot OLD before overwrite), decision = NEW decision,
// first_attempt_at preserved, idempotency_key preserved (immutable once set).
//
// RETURNING populates step.ID, step.GateCount, step.CompletionCount,
// step.LastDecision, step.FirstAttemptAt, step.IdempotencyKey so callers can
// build retry_context without a follow-up read.
//
// Idempotency-key validation (mismatch ⇒ 409) lives in the service layer —
// repository only enforces immutability via COALESCE.
//
// #4249: the upsert never moves a hold. A row holding rejected or expired is
// never replaced by AddStep, whatever the write carries; a row holding pending
// is replaced only by another pending hold (a re-gate that holds again). A
// decision moves a hold through UpdateStepApproval, which moves only a pending
// row (the HITL expiry sweeper writes expired over pending with its own
// statement). When the row
// keeps its hold it keeps every field of the evaluation that made it, so it
// never reports a decision, reason or policies from an evaluation that did not
// land. Service.StepGate refuses those re-evaluations first (ApprovalHoldError);
// this is the same rule in the statement, for a caller that reaches AddStep
// without that check or races past it. A write that lands a NEW hold clears
// the previous decision's approver, so a re-held step never shows an approval
// it has not had. On a kept hold the trailing current_step_index UPDATE still
// runs with the refused write's step index.
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

	// idempotency_key: convert pointer to sql.NullString so nil maps to SQL NULL.
	var idempotencyKey sql.NullString
	if step.IdempotencyKey != nil && *step.IdempotencyKey != "" {
		idempotencyKey = sql.NullString{String: *step.IdempotencyKey, Valid: true}
	}

	query := `
		INSERT INTO workflow_steps (
			workflow_id, step_id, step_index, step_name, step_type,
			decision, decision_reason, policies_evaluated, policies_matched,
			approval_status, step_input, model, provider,
			tokens_in, tokens_out, cost_usd, gate_checked_at,
			gate_count, completion_count, last_decision, first_attempt_at,
			idempotency_key
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13,
			$14, $15, $16, $17,
			1, 0, $6, $17,
			$18
		)
		ON CONFLICT (workflow_id, step_id) DO UPDATE SET
			-- #4249: see upsertKeepsHold; every evaluation field stays with a kept hold.
			step_name = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.step_name ELSE EXCLUDED.step_name END,
			step_type = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.step_type ELSE EXCLUDED.step_type END,
			step_input = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.step_input ELSE EXCLUDED.step_input END,
			model = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.model ELSE EXCLUDED.model END,
			provider = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.provider ELSE EXCLUDED.provider END,
			-- Snapshot OLD decision as last_decision BEFORE we overwrite decision.
			-- This is the value the next gate response will report as
			-- retry_context.last_decision (= "decision of the prior gate call").
			last_decision = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.last_decision ELSE workflow_steps.decision END,
			decision = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.decision ELSE EXCLUDED.decision END,
			decision_reason = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.decision_reason ELSE EXCLUDED.decision_reason END,
			policies_evaluated = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.policies_evaluated ELSE EXCLUDED.policies_evaluated END,
			policies_matched = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.policies_matched ELSE EXCLUDED.policies_matched END,
			approval_status = CASE WHEN ` + upsertKeepsHold + ` THEN workflow_steps.approval_status ELSE EXCLUDED.approval_status END,
			approved_by = CASE WHEN ` + upsertLandsNewHold + ` THEN NULL ELSE workflow_steps.approved_by END,
			approved_at = CASE WHEN ` + upsertLandsNewHold + ` THEN NULL ELSE workflow_steps.approved_at END,
			approval_comment = CASE WHEN ` + upsertLandsNewHold + ` THEN NULL ELSE workflow_steps.approval_comment END,
			tokens_in = EXCLUDED.tokens_in,
			tokens_out = EXCLUDED.tokens_out,
			cost_usd = EXCLUDED.cost_usd,
			gate_checked_at = EXCLUDED.gate_checked_at,
			gate_count = workflow_steps.gate_count + 1,
			-- completion_count is preserved (this is a gate, not a complete).
			-- first_attempt_at is preserved (it's the *first* gate, not the latest).
			-- idempotency_key is immutable once set: keep existing, else take new.
			idempotency_key = COALESCE(workflow_steps.idempotency_key, EXCLUDED.idempotency_key)
		RETURNING id, gate_count, completion_count, last_decision, first_attempt_at, idempotency_key
	`

	var lastDecisionStr sql.NullString
	var firstAttemptAt sql.NullTime
	var returnedIdempotencyKey sql.NullString

	err := r.rowScoped(ctx, query,
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
		idempotencyKey,
	).Scan(
		&step.ID,
		&step.GateCount,
		&step.CompletionCount,
		&lastDecisionStr,
		&firstAttemptAt,
		&returnedIdempotencyKey,
	)

	if err != nil {
		return err
	}

	if lastDecisionStr.Valid {
		step.LastDecision = GateDecision(lastDecisionStr.String)
	}
	if firstAttemptAt.Valid {
		step.FirstAttemptAt = &firstAttemptAt.Time
	}
	if returnedIdempotencyKey.Valid {
		k := returnedIdempotencyKey.String
		step.IdempotencyKey = &k
	} else {
		step.IdempotencyKey = nil
	}

	// Update workflow's current step index
	updateQuery := `
		UPDATE workflows
		SET current_step_index = $1, updated_at = $2
		WHERE workflow_id = $3 AND current_step_index < $1
	`
	_, _ = r.execScoped(ctx, updateQuery, step.StepIndex, now, step.WorkflowID)

	return nil
}

// BumpGateCountCached is called from the cached-hit path of StepGate (Issue
// #1673 Phase 1). When /gate returns a cached decision (the step was already
// evaluated and retry_policy is idempotent), we still want to track that the
// gate was called: gate_count increments, last_decision is snapshotted from
// the current decision so the NEXT call can surface it as
// retry_context.last_decision, and gate_checked_at moves to now.
//
// The stored decision is NOT changed — this is purely a counter/timestamp
// bump. If the row doesn't exist (shouldn't happen on the cached path),
// returns an error so the service layer can fall through to AddStep.
func (r *PostgresRepository) BumpGateCountCached(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	now := time.Now()
	query := `
		UPDATE workflow_steps
		SET gate_count = gate_count + 1,
		    last_decision = decision,
		    gate_checked_at = $1
		WHERE workflow_id = $2 AND step_id = $3
		RETURNING ` + stepSelectColumns + `
	`
	row := r.rowScoped(ctx, query, now, workflowID, stepID)
	step, err := scanWorkflowStepRow(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("step not found: %s/%s", workflowID, stepID)
	}
	return step, err
}

// stepSelectColumns is the canonical column list for reading a workflow_steps row.
// Kept as a constant so GetStep / GetStepDecision / GetStepsForWorkflow /
// BumpGateCountCached stay in sync when new columns are added.
const stepSelectColumns = `
	id, workflow_id, step_id, step_index, step_name, step_type,
	decision, decision_reason, policies_evaluated, policies_matched,
	approval_status, approved_by, approved_at,
	step_input, model, provider, tokens_in, tokens_out, cost_usd,
	step_output, approval_comment, gate_checked_at, step_completed_at,
	gate_count, completion_count, last_decision, first_attempt_at,
	idempotency_key
`

// scanWorkflowStepRow reads one row into a WorkflowStep. Assumes the SELECT
// column order matches stepSelectColumns. Used by GetStep / GetStepDecision
// / BumpGateCountCached / GetStepsForWorkflow so nullable-column handling is
// consistent.
func scanWorkflowStepRow(row interface {
	Scan(dest ...interface{}) error
}) (*WorkflowStep, error) {
	var step WorkflowStep
	var approvalStatus sql.NullString
	var approvedBy sql.NullString
	var approvedAt sql.NullTime
	var approvalComment sql.NullString
	var stepCompletedAt sql.NullTime
	var stepInput []byte
	var stepOutput []byte
	var lastDecisionStr sql.NullString
	var firstAttemptAt sql.NullTime
	var idempotencyKey sql.NullString
	// Nullable text columns (a tool_call/connector_call step legitimately has
	// NULL model/provider; step_name/step_type/decision_reason are nullable too).
	var stepName, stepType, decisionReason, model, provider sql.NullString

	err := row.Scan(
		&step.ID,
		&step.WorkflowID,
		&step.StepID,
		&step.StepIndex,
		&stepName,
		&stepType,
		&step.Decision,
		&decisionReason,
		&step.PoliciesEvaluated,
		&step.PoliciesMatched,
		&approvalStatus,
		&approvedBy,
		&approvedAt,
		&stepInput,
		&model,
		&provider,
		&step.TokensIn,
		&step.TokensOut,
		&step.CostUSD,
		&stepOutput,
		&approvalComment,
		&step.GateCheckedAt,
		&stepCompletedAt,
		&step.GateCount,
		&step.CompletionCount,
		&lastDecisionStr,
		&firstAttemptAt,
		&idempotencyKey,
	)
	if err != nil {
		return nil, err
	}

	step.StepName = stepName.String
	step.StepType = StepType(stepType.String)
	step.DecisionReason = decisionReason.String
	step.Model = model.String
	step.Provider = provider.String

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
	if approvalComment.Valid {
		step.ApprovalComment = approvalComment.String
	}
	if stepCompletedAt.Valid {
		step.StepCompletedAt = &stepCompletedAt.Time
	}
	if stepInput != nil {
		step.StepInput = json.RawMessage(stepInput)
	}
	if stepOutput != nil {
		step.StepOutput = json.RawMessage(stepOutput)
	}
	if lastDecisionStr.Valid {
		step.LastDecision = GateDecision(lastDecisionStr.String)
	}
	if firstAttemptAt.Valid {
		step.FirstAttemptAt = &firstAttemptAt.Time
	}
	if idempotencyKey.Valid {
		k := idempotencyKey.String
		step.IdempotencyKey = &k
	}

	return &step, nil
}

// GetStep retrieves a specific step
func (r *PostgresRepository) GetStep(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	query := `SELECT ` + stepSelectColumns + ` FROM workflow_steps WHERE workflow_id = $1 AND step_id = $2`
	row := r.rowScoped(ctx, query, workflowID, stepID)
	step, err := scanWorkflowStepRow(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("step not found: %s/%s", workflowID, stepID)
	}
	return step, err
}

// GetStepDecision retrieves a step's cached decision for idempotent retry support (#1414).
// Unlike GetStep, this returns nil (not error) when the step has not been evaluated yet,
// making it suitable for the cache-lookup path where "not found" is a normal outcome.
func (r *PostgresRepository) GetStepDecision(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	query := `SELECT ` + stepSelectColumns + ` FROM workflow_steps WHERE workflow_id = $1 AND step_id = $2`
	row := r.rowScoped(ctx, query, workflowID, stepID)
	step, err := scanWorkflowStepRow(row)
	if err == sql.ErrNoRows {
		return nil, nil // Not found is normal — means no cached decision
	}
	return step, err
}

// UpdateStepApproval updates the approval status of a step
func (r *PostgresRepository) UpdateStepApproval(ctx context.Context, workflowID, stepID string, status ApprovalStatus, approvedBy string, comment string) error {
	now := time.Now()
	query := `
		UPDATE workflow_steps
		SET approval_status = $1, approved_by = $2, approved_at = $3, approval_comment = $4
		WHERE workflow_id = $5 AND step_id = $6 AND approval_status = 'pending'
	`
	var commentVal interface{}
	if comment != "" {
		commentVal = comment
	}
	result, err := r.execScoped(ctx, query, status, approvedBy, now, commentVal, workflowID, stepID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// #4249: the statement moves only a PENDING row. Two decisions that
		// both read pending (an approve and a reject racing) cannot both land:
		// the second finds no pending row and is refused, so a rejection that
		// aborted the workflow is never overwritten by an approval.
		return fmt.Errorf("step is not pending approval: %s/%s", workflowID, stepID)
	}

	return nil
}

// MarkStepCompleted marks a step as completed, optionally updating post-execution metrics.
// Also increments completion_count (Issue #1673 Phase 1) so retry_context on
// subsequent gate calls reflects that a prior /complete landed.
//
// Idempotency-key validation happens in the service layer before this is
// called; if the key on the complete request doesn't match the stored key,
// the service returns 409 IDEMPOTENCY_KEY_MISMATCH and never reaches here.
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
		    step_output = COALESCE($7, step_output),
		    completion_count = completion_count + 1
		WHERE workflow_id = $2 AND step_id = $3
	`
	result, err := r.execScoped(ctx, query, now, workflowID, stepID, tokensIn, tokensOut, costUSD, stepOutput)
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
	query := `SELECT ` + stepSelectColumns + ` FROM workflow_steps WHERE workflow_id = $1 ORDER BY step_index ASC`
	var steps []WorkflowStep
	err := r.queryScoped(ctx, query, []interface{}{workflowID}, func(rows *sql.Rows) error {
		for rows.Next() {
			step, err := scanWorkflowStepRow(rows)
			if err != nil {
				return err
			}
			steps = append(steps, *step)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("iterate step rows: %w", err)
	}
	return steps, nil
}

// GetPendingApprovals retrieves steps awaiting approval for a tenant, including workflow-level context.
func (r *PostgresRepository) GetPendingApprovals(ctx context.Context, tenantID string, limit int) ([]PendingApprovalResponse, error) {
	if limit <= 0 {
		limit = 20
	}

	query := `
		SELECT ws.workflow_id, ws.step_id, ws.step_index, ws.step_name, ws.step_type,
			   ws.decision, ws.decision_reason, ws.policies_matched,
			   ws.approval_status, ws.step_input, ws.gate_checked_at,
			   w.workflow_name
		FROM workflow_steps ws
		JOIN workflows w ON ws.workflow_id = w.workflow_id
		WHERE ws.approval_status = 'pending' AND w.tenant_id = $1
		ORDER BY ws.gate_checked_at DESC
		LIMIT $2
	`

	var results []PendingApprovalResponse
	err := r.queryScoped(ctx, query, []interface{}{tenantID, limit}, func(rows *sql.Rows) error {
		for rows.Next() {
			var item PendingApprovalResponse
			var approvalStatus sql.NullString
			// step_name/step_type/decision_reason are nullable columns (a tool_call
			// step legitimately has NULL model/name); step_input is nullable JSONB.
			var stepName, stepType, decisionReason sql.NullString
			var stepInput []byte

			err := rows.Scan(
				&item.WorkflowID,
				&item.StepID,
				&item.StepIndex,
				&stepName,
				&stepType,
				&item.Decision,
				&decisionReason,
				&item.PoliciesMatched,
				&approvalStatus,
				&stepInput,
				&item.CreatedAt,
				&item.WorkflowName,
			)
			if err != nil {
				return err
			}

			item.StepName = stepName.String
			item.StepType = StepType(stepType.String)
			item.DecisionReason = decisionReason.String
			if stepInput != nil {
				item.StepInput = json.RawMessage(stepInput)
			}
			if approvalStatus.Valid {
				as := ApprovalStatus(approvalStatus.String)
				item.ApprovalStatus = &as
			}

			results = append(results, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("iterate pending approval rows: %w", err)
	}
	return results, nil
}

// CountPendingApprovals returns the total number of pending approvals for a tenant.
func (r *PostgresRepository) CountPendingApprovals(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := r.rowScoped(ctx,
		`SELECT COUNT(*) FROM workflow_steps ws
		 JOIN workflows w ON ws.workflow_id = w.workflow_id
		 WHERE ws.approval_status = 'pending' AND w.tenant_id = $1`, tenantID).Scan(&count)
	return count, err
}

// GetPendingPlanApprovals retrieves MAP-backed pending approvals — workflows
// that have a plan_id in metadata (Issue #1680). Each result has PlanID
// populated so reviewer tools can render plan context without a second lookup.
// When planIDFilter is non-empty, results are scoped to that specific plan.
func (r *PostgresRepository) GetPendingPlanApprovals(ctx context.Context, tenantID, planIDFilter string, limit int) ([]PendingApprovalResponse, error) {
	if limit <= 0 {
		limit = 20
	}

	query := `
		SELECT ws.workflow_id, ws.step_id, ws.step_index, ws.step_name, ws.step_type,
			   ws.decision, ws.decision_reason, ws.policies_matched,
			   ws.approval_status, ws.step_input, ws.gate_checked_at,
			   w.workflow_name, w.metadata->>'plan_id'
		FROM workflow_steps ws
		JOIN workflows w ON ws.workflow_id = w.workflow_id
		WHERE ws.approval_status = 'pending'
		  AND w.tenant_id = $1
		  AND w.metadata->>'plan_id' IS NOT NULL
	`
	args := []interface{}{tenantID}
	if planIDFilter != "" {
		query += ` AND w.metadata->>'plan_id' = $2 ORDER BY ws.gate_checked_at DESC LIMIT $3`
		args = append(args, planIDFilter, limit)
	} else {
		query += ` ORDER BY ws.gate_checked_at DESC LIMIT $2`
		args = append(args, limit)
	}

	var results []PendingApprovalResponse
	err := r.queryScoped(ctx, query, args, func(rows *sql.Rows) error {
		for rows.Next() {
			var item PendingApprovalResponse
			var approvalStatus sql.NullString
			var planID sql.NullString
			// Nullable columns (see GetPendingApprovals): guard against NULL scan.
			var stepName, stepType, decisionReason sql.NullString
			var stepInput []byte

			err := rows.Scan(
				&item.WorkflowID,
				&item.StepID,
				&item.StepIndex,
				&stepName,
				&stepType,
				&item.Decision,
				&decisionReason,
				&item.PoliciesMatched,
				&approvalStatus,
				&stepInput,
				&item.CreatedAt,
				&item.WorkflowName,
				&planID,
			)
			if err != nil {
				return err
			}

			item.StepName = stepName.String
			item.StepType = StepType(stepType.String)
			item.DecisionReason = decisionReason.String
			if stepInput != nil {
				item.StepInput = json.RawMessage(stepInput)
			}
			if approvalStatus.Valid {
				as := ApprovalStatus(approvalStatus.String)
				item.ApprovalStatus = &as
			}
			if planID.Valid {
				item.PlanID = planID.String
			}

			results = append(results, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("iterate pending plan approval rows: %w", err)
	}
	return results, nil
}

// CountPendingPlanApprovals returns the total number of MAP-backed pending
// approvals for a tenant, optionally scoped to a specific plan_id.
func (r *PostgresRepository) CountPendingPlanApprovals(ctx context.Context, tenantID, planIDFilter string) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM workflow_steps ws
			  JOIN workflows w ON ws.workflow_id = w.workflow_id
			  WHERE ws.approval_status = 'pending'
			    AND w.tenant_id = $1
			    AND w.metadata->>'plan_id' IS NOT NULL`
	args := []interface{}{tenantID}
	if planIDFilter != "" {
		query += ` AND w.metadata->>'plan_id' = $2`
		args = append(args, planIDFilter)
	}
	err := r.queryRowScoped(ctx, query, args, &count)
	return count, err
}
