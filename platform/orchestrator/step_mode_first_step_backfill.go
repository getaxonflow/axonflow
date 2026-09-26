// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// THE UPGRADE'S ONE-TIME BACKFILL OF STEP-MODE FIRST-STEP RECORDS (#4249 row
// 5701284807, master's ruling on #4385).
//
// From this release a step-mode plan's first step, which runs ungated, leaves a
// record before it runs (workflow_control.RecordStepRun), so "no row for step
// 0" means "never ran" and the resume runs it. A plan in flight at the upgrade
// ran its first step before the record existed: no row, and a later step's gate
// its own resume wrote. Read as "never ran", its next resume would run the first
// step a second time. Such a plan gets its record written, reason
// backfilled_at_upgrade, so the data says what happened.
//
// It is decided per plan by backfillStepModeFirstStep, from the cut-over
// instant: migration 187's applied_at (migrations/core/187_*). A plan whose
// workflow was created before that instant, is not terminal, has no row for its
// first step and has a row for a later step of its own is backfilled; a plan
// created after it wrote its own record, so it never is. The decision runs
// twice, both writing through RecordStepRun, which writes a record once:
//   - at boot (runStepModeFirstStepBackfill), for every step-mode plan in flight;
//   - in the resume, for the plan being resumed, because the migration is
//     applied by the agent and this process can boot before it.
// The only exposure is a plan in flight at the instant for which another caller
// wrote a later step's gate before its first resume: that gate reads as the
// plan's own, and the first step is recorded as ran.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	logutil "axonflow/platform/shared/logger"
)

// The migration whose applied_at is the cut-over, and the backfill's actor.
const (
	stepModeCutoverVersion = "187"
	stepModeCutoverName    = "step_mode_first_step_record_cutover"
	// stepModeBackfillActor is the actor a backfilled record names: the
	// upgrade, never a person.
	stepModeBackfillActor = "axonflow-upgrade"
)

// stepModeCutoverSource reads the cut-over instant. recorded is false while
// migration 187 has not been applied.
type stepModeCutoverSource func(ctx context.Context) (at time.Time, recorded bool, err error)

// stepModeCutover is the process's source, set at boot (sqlStepModeCutover).
// Unset, no cut-over is recorded.
var stepModeCutover stepModeCutoverSource = func(context.Context) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

// sqlStepModeCutover reads migration 187's applied_at from schema_migrations,
// by version AND name (an enterprise migration can share a version number).
func sqlStepModeCutover(db *sql.DB) stepModeCutoverSource {
	return func(ctx context.Context) (time.Time, bool, error) {
		var at time.Time
		err := db.QueryRowContext(ctx,
			`SELECT applied_at FROM schema_migrations WHERE version = $1 AND name = $2 AND success = true`,
			stepModeCutoverVersion, stepModeCutoverName).Scan(&at)
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, false, nil
		}
		if err != nil {
			return time.Time{}, false, err
		}
		return at, true, nil
	}
}

// stepModeFirstStepAmbiguous reports whether a step-mode plan's workflow is in
// the state only the cut-over can decide: no row for the plan's first step, and
// a row for a later step of its own.
func stepModeFirstStepAmbiguous(steps []WorkflowStep, wf *workflow_control.Workflow) bool {
	if len(steps) == 0 || wf == nil {
		return false
	}
	first := mapStepGateID(0, steps[0])
	own := planStepGateIDs(steps)
	hasFirst, hasLater := false, false
	for _, row := range wf.Steps {
		switch {
		case row.StepID == first:
			hasFirst = true
		case own[row.StepID]:
			hasLater = true
		}
	}
	return !hasFirst && hasLater
}

// backfillStepModeFirstStep writes a step-mode plan's first-step record when
// its workflow was created before cutover and is in the ambiguous state. It
// reports whether it wrote one; a record another writer wrote first is not an
// error.
func backfillStepModeFirstStep(ctx context.Context, svc *workflow_control.Service, steps []WorkflowStep, wf *workflow_control.Workflow, cutover time.Time) (bool, error) {
	if wf.IsTerminal() || !wf.CreatedAt.Before(cutover) || !stepModeFirstStepAmbiguous(steps, wf) {
		return false, nil
	}
	first := steps[0]
	firstType, err := mapStepTypeToWCP(first.Type)
	if err != nil {
		return false, err
	}
	err = svc.RecordStepRun(ctx, workflow_control.StepRunRecord{
		WorkflowID: wf.WorkflowID,
		StepID:     mapStepGateID(0, first),
		StepIndex:  1,
		StepName:   first.Name,
		StepType:   firstType,
		StepInput:  mapHeldStepInput(first),
		Reason:     workflow_control.StepRunReasonBackfilledAtUpgrade,
		TenantID:   wf.TenantID,
		OrgID:      wf.OrgID,
		UserID:     stepModeBackfillActor,
	})
	if errors.Is(err, workflow_control.ErrStepAlreadyRecorded) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// errStepModeCutoverNotRecorded refuses a resume that meets the ambiguous state
// before migration 187 is applied: running the first step could run it twice.
var errStepModeCutoverNotRecorded = errors.New("the upgrade's cut-over for step-mode first-step records (migration 187) is not recorded yet, so whether this plan's first step ran cannot be decided; resume it once migrations have run")

// stepModeFirstStepOnResume is the backfill for the plan being resumed. It
// reports whether it wrote a record, and refuses (errStepModeCutoverNotRecorded)
// the ambiguous state while the cut-over is not recorded.
func stepModeFirstStepOnResume(ctx context.Context, svc *workflow_control.Service, steps []WorkflowStep, wf *workflow_control.Workflow) (bool, error) {
	if !stepModeFirstStepAmbiguous(steps, wf) {
		return false, nil
	}
	cutover, recorded, err := stepModeCutover(ctx)
	if err != nil {
		return false, fmt.Errorf("reading the step-mode cut-over: %w", err)
	}
	if !recorded {
		return false, errStepModeCutoverNotRecorded
	}
	return backfillStepModeFirstStep(ctx, svc, steps, wf, cutover)
}

// runStepModeFirstStepBackfill is the boot pass: every step-mode plan still
// executing is decided once. It does nothing while migration 187 is not
// applied. A plan it cannot read or resolve is logged and left to the resume.
// stepModePlanCandidate is one step-mode plan the boot pass decides.
type stepModePlanCandidate struct{ planID, orgID string }

// stepModePlanLister lists every step-mode plan still executing.
type stepModePlanLister func(ctx context.Context) ([]stepModePlanCandidate, error)

// sqlStepModePlans lists them from the plans table, across organizations.
func sqlStepModePlans(db *sql.DB) stepModePlanLister {
	return func(ctx context.Context) ([]stepModePlanCandidate, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT plan_id, COALESCE(org_id, '') FROM plans WHERE execution_mode = 'step' AND status = $1`,
			planning.PlanStatusExecuting)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		var out []stepModePlanCandidate
		for rows.Next() {
			var c stepModePlanCandidate
			if err := rows.Scan(&c.planID, &c.orgID); err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}
}

func runStepModeFirstStepBackfill(ctx context.Context, list stepModePlanLister, plans *planning.Service, svc *workflow_control.Service) (int, error) {
	cutover, recorded, err := stepModeCutover(ctx)
	if err != nil {
		return 0, fmt.Errorf("reading the step-mode cut-over: %w", err)
	}
	if !recorded {
		log.Printf("[StepModeBackfill] migration %s_%s is not applied; nothing is backfilled (a resume decides its own plan)", stepModeCutoverVersion, stepModeCutoverName)
		return 0, nil
	}
	candidates, err := list(ctx)
	if err != nil {
		return 0, fmt.Errorf("listing step-mode plans: %w", err)
	}
	written := 0
	for _, c := range candidates {
		ok, err := backfillStepModePlan(ctx, plans, svc, c.planID, c.orgID, cutover)
		if err != nil {
			log.Printf("[StepModeBackfill] plan %s: %v (left to its resume)", logutil.Sanitize(c.planID), err)
			continue
		}
		if ok {
			written++
		}
	}
	log.Printf("[StepModeBackfill] %d step-mode plan(s) in flight, %d first-step record(s) backfilled", len(candidates), written)
	return written, nil
}

// backfillStepModePlan decides one plan for the boot pass.
func backfillStepModePlan(ctx context.Context, plans *planning.Service, svc *workflow_control.Service, planID, orgID string, cutover time.Time) (bool, error) {
	plan, err := plans.GetPlan(ctx, planID, orgID)
	if err != nil {
		return false, fmt.Errorf("reading the plan: %w", err)
	}
	target, refusal, err := resolvePlanWorkflow(ctx, svc, plan, plan.TenantID, plan.OrgID)
	if err != nil {
		return false, fmt.Errorf("resolving its workflow: %w", err)
	}
	if refusal != nil {
		return false, nil
	}
	wf, err := svc.GetWorkflow(ctx, target.WorkflowID, plan.TenantID, plan.OrgID)
	if err != nil {
		return false, fmt.Errorf("reading its workflow: %w", err)
	}
	var def Workflow
	if err := json.Unmarshal(plan.WorkflowDefinition, &def); err != nil {
		return false, fmt.Errorf("reading its definition: %w", err)
	}
	return backfillStepModeFirstStep(ctx, svc, presentedSteps(def.Spec.Steps), wf, cutover)
}
