// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// A STEP THAT RUNS UNGATED LEAVES A RECORD (#4249 row 5701284807).
//
// Step mode runs a plan's first step with no gate, by design, and used to leave
// no row for it. A plan's steps run in order, and the resume decides that from
// the rows: with no row for step 0, "ran ungated" and "never ran" were the same
// state, so another caller's gate on a later step, written before the first
// resume, made the resume run that step and never step 0. RecordStepRun writes
// the missing row: an ALLOW with no approval status, a reason naming why it is
// not a gate decision, and an audit row beside it. It never disguises an
// ungated run as an approved one.

// Step-run record reasons. Each is the row's decision_reason and the audit
// row's reason, so a reader tells a recorded ungated run from a gate decision
// and from a record written at upgrade.
const (
	// StepRunReasonStepModeFirstStep is a step-mode plan's first step, which
	// runs ungated by design, recorded by the resume before it runs.
	StepRunReasonStepModeFirstStep = "step_mode_first_step_ungated"
	// StepRunReasonBackfilledAtUpgrade is the same record written at upgrade
	// for a step-mode plan in flight whose first step ran before the record
	// existed.
	StepRunReasonBackfilledAtUpgrade = "backfilled_at_upgrade"
)

// ErrStepAlreadyRecorded refuses a step-run record for a step that already has
// a row: the record is written once, so a doubled resume cannot run the step a
// second time through it.
var ErrStepAlreadyRecorded = errors.New("step_already_recorded")

// StepRunRecord is one step-run record to write.
type StepRunRecord struct {
	WorkflowID string
	StepID     string
	// StepIndex is the step's 1-based position in the plan, the index the
	// executor's gate rows carry (step 0's is 1). Zero stamps the workflow's
	// next index.
	StepIndex int
	StepName  string
	StepType  StepType
	StepInput map[string]interface{}
	// Reason is StepRunReasonStepModeFirstStep or
	// StepRunReasonBackfilledAtUpgrade.
	Reason string
	// The credential the record is written for: the resuming caller, or the
	// upgrade for a backfill.
	TenantID, OrgID, UserID, ClientID string
}

// RecordStepRun writes rec's step as an ALLOW row with no approval status, once.
// It is refused (ErrStepAlreadyRecorded) when the step already has a row, and
// ErrWorkflowNotFound outside the caller's tenancy. Unlike StepGate it is not
// refused while another step holds a pending approval: it adds no approval, so
// "one pending approval per workflow" still holds.
func (s *Service) RecordStepRun(ctx context.Context, rec StepRunRecord) error {
	if rec.Reason != StepRunReasonStepModeFirstStep && rec.Reason != StepRunReasonBackfilledAtUpgrade {
		return fmt.Errorf("step-run record: reason %q is not a declared step-run reason", rec.Reason)
	}
	workflow, err := s.repo.GetByID(ctx, rec.WorkflowID)
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}
	if !workflowBelongsTo(workflow, rec.TenantID, rec.OrgID) {
		return fmt.Errorf("%s: %w", rec.WorkflowID, ErrWorkflowNotFound)
	}
	if workflow.IsTerminal() {
		return fmt.Errorf("workflow %s is in terminal state %s; no step-run record is written", rec.WorkflowID, workflow.Status)
	}
	input := rec.StepInput
	if input == nil {
		input = map[string]interface{}{}
	}
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("step-run record: the step input cannot be recorded: %w", err)
	}
	// A backfilled record is a first step that already ran, so it is recorded
	// completed; the resume's own record is written before the step runs and is
	// completed when it has.
	completions := 0
	if rec.Reason == StepRunReasonBackfilledAtUpgrade {
		completions = 1
	}
	stepIndex := rec.StepIndex
	if stepIndex <= 0 {
		stepIndex = workflow.CurrentStepIndex + 1
	}
	step := &WorkflowStep{
		CompletionCount:   completions,
		WorkflowID:        rec.WorkflowID,
		StepID:            rec.StepID,
		StepIndex:         stepIndex,
		StepName:          rec.StepName,
		StepType:          rec.StepType,
		Decision:          GateDecisionAllow,
		DecisionReason:    rec.Reason,
		PoliciesEvaluated: json.RawMessage("[]"),
		PoliciesMatched:   json.RawMessage("[]"),
		StepInput:         inputJSON,
	}
	inserted, err := s.repo.InsertStepRunRecord(ctx, step)
	if err != nil {
		return fmt.Errorf("failed to record the step run: %w", err)
	}
	if !inserted {
		return fmt.Errorf("%w: step %s of workflow %s already has a row", ErrStepAlreadyRecorded, rec.StepID, rec.WorkflowID)
	}
	s.logAudit(ctx, &WorkflowAuditEntry{
		WorkflowID:   rec.WorkflowID,
		WorkflowName: workflow.WorkflowName,
		StepID:       rec.StepID,
		StepName:     rec.StepName,
		Operation:    "step_gate",
		Decision:     string(GateDecisionAllow),
		Reason:       rec.Reason,
		TenantID:     workflow.TenantID,
		OrgID:        workflow.OrgID,
		ClientID:     rec.ClientID,
		UserID:       rec.UserID,
		Metadata: map[string]interface{}{
			"step_run_record": true,
			"gated":           false,
		},
	})
	return nil
}

// stepRunInsert is the insert AddStep makes, refusing rather than updating an
// existing row.
const stepRunInsert = `
	INSERT INTO workflow_steps (
		workflow_id, step_id, step_index, step_name, step_type,
		decision, decision_reason, policies_evaluated, policies_matched,
		approval_status, step_input, model, provider,
		tokens_in, tokens_out, cost_usd, gate_checked_at,
		gate_count, completion_count, last_decision, first_attempt_at
	) VALUES (
		$1, $2, $3, $4, $5,
		$6, $7, $8, $9,
		NULL, $10, '', '',
		0, 0, 0, $11,
		1, $12, $6, $11
	)
	ON CONFLICT (workflow_id, step_id) DO NOTHING
	RETURNING id`

// InsertStepRunRecord writes step as a NEW row and never touches an existing
// one: inserted is false when the step already has a row. It is the one write
// of a step-run record (Service.RecordStepRun), atomic against a concurrent
// one.
func (r *PostgresRepository) InsertStepRunRecord(ctx context.Context, step *WorkflowStep) (bool, error) {
	now := time.Now()
	step.GateCheckedAt = now
	err := r.db.QueryRowContext(ctx, stepRunInsert,
		step.WorkflowID, step.StepID, step.StepIndex, step.StepName, step.StepType,
		step.Decision, step.DecisionReason, step.PoliciesEvaluated, step.PoliciesMatched,
		step.StepInput, now, step.CompletionCount,
	).Scan(&step.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// As AddStep does: the workflow's current step index follows a written row.
	_, _ = r.db.ExecContext(ctx, `
		UPDATE workflows
		SET current_step_index = $1, updated_at = $2
		WHERE workflow_id = $3 AND current_step_index < $1
	`, step.StepIndex, now, step.WorkflowID)
	return true, nil
}
