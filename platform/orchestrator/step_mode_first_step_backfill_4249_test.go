// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4249 row 5701284807, master's ruling on #4385: a step-mode plan in flight at
// the upgrade ran its first step before that step left a record. The upgrade
// writes the record (backfilled_at_upgrade) for a plan created before migration
// 187's applied_at, so its next resume runs step 1, not step 0 again.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"axonflow/platform/orchestrator/workflow_control"
)

// withStepModeCutover installs the cut-over the backfill and the resume read.
func withStepModeCutover(t *testing.T, at time.Time, recorded bool) {
	t.Helper()
	previous := stepModeCutover
	stepModeCutover = func(context.Context) (time.Time, bool, error) { return at, recorded, nil }
	t.Cleanup(func() { stepModeCutover = previous })
}

// inFlightStepModePlan is a step-mode plan in the state a plan in flight at the
// upgrade is in: its first step ran with no record, and its resume gated step 1.
func inFlightStepModePlan(t *testing.T, planID string) *realResumeFixture {
	t.Helper()
	f := executeRealPlan(t, planID, "step", nil)
	holdLaterStepAsAnotherCaller(t, f)
	return f
}

func listingOnly(planID string) stepModePlanLister {
	return func(context.Context) ([]stepModePlanCandidate, error) {
		return []stepModePlanCandidate{{planID: planID, orgID: "org_1"}}, nil
	}
}

func TestAStepModePlanInFlightAtTheCutoverIsBackfilledAndItsNextResumeRunsStepOne(t *testing.T) {
	f := inFlightStepModePlan(t, "plan_backfill_before")
	withStepModeCutover(t, time.Now().Add(time.Hour), true)

	written, err := runStepModeFirstStepBackfill(context.Background(), listingOnly(f.planID), planService, workflowControlService)
	if err != nil || written != 1 {
		t.Fatalf("boot pass = %d, %v; want 1 record written", written, err)
	}
	first := f.row(t, "step_0_fetch")
	if first == nil || first.DecisionReason != workflow_control.StepRunReasonBackfilledAtUpgrade || first.CompletionCount != 1 ||
		first.Decision != workflow_control.GateDecisionAllow || first.ApprovalStatus != nil {
		t.Fatalf("step_0_fetch = %+v, want an allow recorded %s, completed once, no approval", first, workflow_control.StepRunReasonBackfilledAtUpgrade)
	}
	// A SECOND BOOT WRITES NOTHING.
	if written, err := runStepModeFirstStepBackfill(context.Background(), listingOnly(f.planID), planService, workflowControlService); err != nil || written != 0 {
		t.Errorf("second boot pass = %d, %v; want nothing written", written, err)
	}

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "report" {
		t.Errorf("resume: status %d ran %v body %s, want step 1 (report) run and step 0 not run again", w.Code, *f.ran, w.Body.String())
	}
}

func TestAStepModePlanCreatedAfterTheCutoverIsNotBackfilled(t *testing.T) {
	f := inFlightStepModePlan(t, "plan_backfill_after")
	withStepModeCutover(t, time.Now().Add(-time.Hour), true)

	if written, err := runStepModeFirstStepBackfill(context.Background(), listingOnly(f.planID), planService, workflowControlService); err != nil || written != 0 {
		t.Fatalf("boot pass = %d, %v; want nothing written for a plan created after the cut-over", written, err)
	}
	if f.row(t, "step_0_fetch") != nil {
		t.Fatalf("a plan created after the cut-over was backfilled")
	}
	w := resumeThePlan(t, f.planID)
	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Errorf("resume: status %d ran %v body %s, want its first step run", w.Code, *f.ran, w.Body.String())
	}
}

// The migration is applied by the agent, so the orchestrator can boot first:
// the resume decides its own plan, and refuses while the cut-over is not
// recorded rather than run a first step that may have run.
func TestAResumeRefusesTheUndecidableFirstStepWhileTheCutoverIsNotRecorded(t *testing.T) {
	f := inFlightStepModePlan(t, "plan_backfill_unrecorded")
	withStepModeCutover(t, time.Time{}, false)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusConflict || len(*f.ran) != 0 {
		t.Fatalf("status %d ran %v body %s, want 409 and nothing run", w.Code, *f.ran, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "migration 187") {
		t.Errorf("the refusal %s does not name the missing cut-over", w.Body.String())
	}
}

func TestAResumeBackfillsItsOwnPlanWhenTheBootPassDidNot(t *testing.T) {
	f := inFlightStepModePlan(t, "plan_backfill_on_resume")
	withStepModeCutover(t, time.Now().Add(time.Hour), true)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "report" {
		t.Fatalf("status %d ran %v body %s, want step 1 run and step 0 not run again", w.Code, *f.ran, w.Body.String())
	}
	if first := f.row(t, "step_0_fetch"); first == nil || first.DecisionReason != workflow_control.StepRunReasonBackfilledAtUpgrade {
		t.Errorf("step_0_fetch = %+v, want the resume's backfilled record", first)
	}
}
