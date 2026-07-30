// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"axonflow/platform/shared/tenantscope"
)

// CheckpointType classifies how the checkpoint was created.
type CheckpointType string

const (
	// CheckpointStepGate is a checkpoint created at a standard step-gate evaluation.
	CheckpointStepGate CheckpointType = "step_gate"

	// CheckpointApprovalBoundary is a checkpoint where the step required human approval.
	// These are particularly important for resume because the approval decision
	// may have changed since the checkpoint was created.
	CheckpointApprovalBoundary CheckpointType = "approval_boundary"
)

// Checkpoint represents a governance-aware resume boundary at a step-gate evaluation.
// Checkpoints are created automatically during StepGate() calls and capture the
// decision context needed to safely resume a workflow from that point.
type Checkpoint struct {
	ID                int64           `json:"id" db:"id"`
	WorkflowID        string          `json:"workflow_id" db:"workflow_id"`
	StepID            string          `json:"step_id" db:"step_id"`
	StepIndex         int             `json:"step_index" db:"step_index"`
	StepType          StepType        `json:"step_type,omitempty" db:"step_type"`
	StepName          string          `json:"step_name,omitempty" db:"step_name"`
	CheckpointType    CheckpointType  `json:"checkpoint_type" db:"checkpoint_type"`
	GateDecision      string          `json:"gate_decision" db:"gate_decision"`
	GateReason        string          `json:"gate_reason,omitempty" db:"gate_reason"`
	PoliciesEvaluated json.RawMessage `json:"policies_evaluated,omitempty" db:"policies_evaluated"`
	PoliciesMatched   json.RawMessage `json:"policies_matched,omitempty" db:"policies_matched"`
	StepInput         json.RawMessage `json:"step_input,omitempty" db:"step_input"`
	// ToolContext is the serialized tool-level context for per-tool governance.
	// Stored as JSON so resume can reconstruct the full gate request.
	ToolContext   json.RawMessage `json:"tool_context,omitempty" db:"tool_context"`
	Model         string          `json:"model,omitempty" db:"model"`
	Provider      string          `json:"provider,omitempty" db:"provider"`
	IsResumable   bool            `json:"is_resumable" db:"is_resumable"`
	ResumeCount   int             `json:"resume_count" db:"resume_count"`
	LastResumedAt *time.Time      `json:"last_resumed_at,omitempty" db:"last_resumed_at"`
	OrgID         string          `json:"org_id,omitempty" db:"org_id"`
	TenantID      string          `json:"tenant_id,omitempty" db:"tenant_id"`
	UserID        string          `json:"user_id,omitempty" db:"user_id"`
	ClientID      string          `json:"client_id,omitempty" db:"client_id"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
}

// CheckpointListResponse is the API response for listing checkpoints.
type CheckpointListResponse struct {
	Checkpoints []Checkpoint `json:"checkpoints"`
	WorkflowID  string       `json:"workflow_id"`
}

// ResumeFromCheckpointResponse is the API response after resuming from a checkpoint.
type ResumeFromCheckpointResponse struct {
	WorkflowID            string `json:"workflow_id"`
	ResumedFromCheckpoint string `json:"resumed_from_checkpoint"` // step_id
	ResumedFromIndex      int    `json:"resumed_from_index"`
	NewDecision           string `json:"new_decision"`
	DecisionSource        string `json:"decision_source"` // always "fresh" since resume re-evaluates
	ResumeCount           int    `json:"resume_count"`
	Message               string `json:"message"`
}

// --- PostgreSQL checkpoint repository methods ---

// CreateCheckpoint inserts or updates a checkpoint for a step-gate boundary.
// Uses upsert so re-evaluations (retry_policy=reevaluate) update the existing checkpoint.
func (r *PostgresRepository) CreateCheckpoint(ctx context.Context, cp *Checkpoint) error {
	// #3065 (R3 round 1): ResumeFromCheckpoint now authorizes the checkpoint
	// row on its own keys, so a checkpoint written without them would be
	// permanently non-resumable. workflow_checkpoints is covered by migration
	// core/156 alongside the tables it gates; this is the application half, so
	// the refusal names the cause instead of surfacing a constraint violation.
	// The upsert below also refreshes org_id/tenant_id on conflict, so a row
	// written before this guard is repaired on its next gate rather than
	// staying stuck.
	if err := tenantscope.ValidateRowKeys(cp.OrgID, cp.TenantID); err != nil {
		return fmt.Errorf("refusing to persist checkpoint for workflow %s step %s with no org/tenant key: %w",
			cp.WorkflowID, cp.StepID, err)
	}

	query := `
		INSERT INTO workflow_checkpoints (
			workflow_id, step_id, step_index, step_type, step_name, checkpoint_type,
			gate_decision, gate_reason, policies_evaluated, policies_matched,
			step_input, tool_context, model, provider,
			is_resumable, org_id, tenant_id, user_id, client_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		ON CONFLICT (workflow_id, step_id) DO UPDATE SET
			step_type = EXCLUDED.step_type,
			step_name = EXCLUDED.step_name,
			checkpoint_type = EXCLUDED.checkpoint_type,
			gate_decision = EXCLUDED.gate_decision,
			gate_reason = EXCLUDED.gate_reason,
			policies_evaluated = EXCLUDED.policies_evaluated,
			policies_matched = EXCLUDED.policies_matched,
			step_input = EXCLUDED.step_input,
			tool_context = EXCLUDED.tool_context,
			model = EXCLUDED.model,
			provider = EXCLUDED.provider,
			is_resumable = EXCLUDED.is_resumable,
			org_id = EXCLUDED.org_id,
			tenant_id = EXCLUDED.tenant_id,
			user_id = EXCLUDED.user_id,
			client_id = EXCLUDED.client_id
		RETURNING id, created_at
	`

	policiesEvaluated := cp.PoliciesEvaluated
	if policiesEvaluated == nil {
		policiesEvaluated = json.RawMessage("[]")
	}
	policiesMatched := cp.PoliciesMatched
	if policiesMatched == nil {
		policiesMatched = json.RawMessage("[]")
	}
	// JSONB columns require valid JSON or NULL — Go nil becomes a zero-length
	// []byte which PostgreSQL rejects as invalid JSON syntax.
	stepInput := cp.StepInput
	if stepInput == nil {
		stepInput = json.RawMessage("{}")
	}
	var toolContext interface{} = cp.ToolContext
	if cp.ToolContext == nil {
		toolContext = nil // sql/driver treats Go nil as SQL NULL for JSONB
	}

	return r.db.QueryRowContext(ctx, query,
		cp.WorkflowID, cp.StepID, cp.StepIndex, cp.StepType, cp.StepName, cp.CheckpointType,
		cp.GateDecision, cp.GateReason, policiesEvaluated, policiesMatched,
		stepInput, toolContext, cp.Model, cp.Provider,
		cp.IsResumable, cp.OrgID, cp.TenantID, cp.UserID, cp.ClientID,
	).Scan(&cp.ID, &cp.CreatedAt)
}

// ListCheckpoints returns all checkpoints for a workflow, ordered by step_index ascending.
func (r *PostgresRepository) ListCheckpoints(ctx context.Context, workflowID string) ([]Checkpoint, error) {
	query := `
		SELECT id, workflow_id, step_id, step_index, step_type, step_name, checkpoint_type,
			gate_decision, gate_reason, policies_evaluated, policies_matched,
			step_input, tool_context, model, provider,
			is_resumable, resume_count, last_resumed_at,
			org_id, tenant_id, user_id, client_id, created_at
		FROM workflow_checkpoints
		WHERE workflow_id = $1
		ORDER BY step_index ASC
	`

	rows, err := r.db.QueryContext(ctx, query, workflowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checkpoints []Checkpoint
	for rows.Next() {
		var cp Checkpoint
		var lastResumedAt sql.NullTime
		var toolContextBytes []byte
		err := rows.Scan(
			&cp.ID, &cp.WorkflowID, &cp.StepID, &cp.StepIndex, &cp.StepType, &cp.StepName, &cp.CheckpointType,
			&cp.GateDecision, &cp.GateReason, &cp.PoliciesEvaluated, &cp.PoliciesMatched,
			&cp.StepInput, &toolContextBytes, &cp.Model, &cp.Provider,
			&cp.IsResumable, &cp.ResumeCount, &lastResumedAt,
			&cp.OrgID, &cp.TenantID, &cp.UserID, &cp.ClientID, &cp.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		if lastResumedAt.Valid {
			cp.LastResumedAt = &lastResumedAt.Time
		}
		if toolContextBytes != nil {
			cp.ToolContext = json.RawMessage(toolContextBytes)
		}
		checkpoints = append(checkpoints, cp)
	}

	if checkpoints == nil {
		checkpoints = []Checkpoint{}
	}
	return checkpoints, rows.Err()
}

// GetLastResumableCheckpoint returns the most recent resumable checkpoint for a workflow.
// Returns nil (not error) if no resumable checkpoint exists.
func (r *PostgresRepository) GetLastResumableCheckpoint(ctx context.Context, workflowID string) (*Checkpoint, error) {
	query := `
		SELECT id, workflow_id, step_id, step_index, step_type, step_name, checkpoint_type,
			gate_decision, gate_reason, policies_evaluated, policies_matched,
			step_input, tool_context, model, provider,
			is_resumable, resume_count, last_resumed_at,
			org_id, tenant_id, user_id, client_id, created_at
		FROM workflow_checkpoints
		WHERE workflow_id = $1 AND is_resumable = true
		ORDER BY step_index DESC
		LIMIT 1
	`

	var cp Checkpoint
	var lastResumedAt sql.NullTime
	var toolContextBytes2 []byte
	err := r.db.QueryRowContext(ctx, query, workflowID).Scan(
		&cp.ID, &cp.WorkflowID, &cp.StepID, &cp.StepIndex, &cp.StepType, &cp.StepName, &cp.CheckpointType,
		&cp.GateDecision, &cp.GateReason, &cp.PoliciesEvaluated, &cp.PoliciesMatched,
		&cp.StepInput, &toolContextBytes2, &cp.Model, &cp.Provider,
		&cp.IsResumable, &cp.ResumeCount, &lastResumedAt,
		&cp.OrgID, &cp.TenantID, &cp.UserID, &cp.ClientID, &cp.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lastResumedAt.Valid {
		cp.LastResumedAt = &lastResumedAt.Time
	}
	if toolContextBytes2 != nil {
		cp.ToolContext = json.RawMessage(toolContextBytes2)
	}
	return &cp, nil
}

// GetCheckpointByID returns a specific checkpoint by its database ID.
// Returns nil (not error) if the checkpoint doesn't exist.
func (r *PostgresRepository) GetCheckpointByID(ctx context.Context, id int64) (*Checkpoint, error) {
	query := `
		SELECT id, workflow_id, step_id, step_index, step_type, step_name, checkpoint_type,
			gate_decision, gate_reason, policies_evaluated, policies_matched,
			step_input, tool_context, model, provider,
			is_resumable, resume_count, last_resumed_at,
			org_id, tenant_id, user_id, client_id, created_at
		FROM workflow_checkpoints
		WHERE id = $1
	`

	var cp Checkpoint
	var lastResumedAt sql.NullTime
	var toolContextBytes3 []byte
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&cp.ID, &cp.WorkflowID, &cp.StepID, &cp.StepIndex, &cp.StepType, &cp.StepName, &cp.CheckpointType,
		&cp.GateDecision, &cp.GateReason, &cp.PoliciesEvaluated, &cp.PoliciesMatched,
		&cp.StepInput, &toolContextBytes3, &cp.Model, &cp.Provider,
		&cp.IsResumable, &cp.ResumeCount, &lastResumedAt,
		&cp.OrgID, &cp.TenantID, &cp.UserID, &cp.ClientID, &cp.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if toolContextBytes3 != nil {
		cp.ToolContext = json.RawMessage(toolContextBytes3)
	}
	if lastResumedAt.Valid {
		cp.LastResumedAt = &lastResumedAt.Time
	}
	return &cp, nil
}

// IncrementResumeCount atomically increments the resume count and updates last_resumed_at.
// Returns an error if the checkpoint doesn't exist (e.g., deleted between gate call and increment).
func (r *PostgresRepository) IncrementResumeCount(ctx context.Context, id int64) error {
	query := `
		UPDATE workflow_checkpoints
		SET resume_count = resume_count + 1, last_resumed_at = $1
		WHERE id = $2
	`
	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("checkpoint %d not found", id)
	}
	return nil
}
