// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"axonflow/platform/testutil"
)

// #4249 (row 5699811991): the confirm/step executor's workflow is bound to the
// plan once, while the plan is executing, and read back from execution_result.
// The same cells run against the Postgres statement and the mock.

// bindingRepositories names the repositories the binding cells run against.
// Each is built inside its own subtest, so a runner without Docker skips only
// the Postgres subtest and still runs the mock cells.
func bindingRepositories() map[string]func(t *testing.T) Repository {
	return map[string]func(t *testing.T) Repository{
		"mock": func(t *testing.T) Repository { return NewMockRepository() },
		"postgres": func(t *testing.T) Repository {
			t.Helper()
			testutil.SkipIfNoDocker(t)
			pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
			pg.RunMigration(t, migrationFile(t, "037_plans.sql")+"\n"+migrationFile(t, "047_plan_versioning.sql"))
			return NewPostgresRepository(pg.DB)
		},
	}
}

func migrationFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../../migrations/core/" + name)
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return string(b)
}

func savedPlan(t *testing.T, repo Repository, id string, status PlanStatus) {
	t.Helper()
	savedPlanInMode(t, repo, id, status, "confirm", true)
}

// savedPlanInMode saves a pending plan and, for status executing, marks it the
// way this release does (marked=true: with an empty binding) or the way a plan
// executing from before the binding was marked (marked=false).
func savedPlanInMode(t *testing.T, repo Repository, id string, status PlanStatus, mode string, marked bool) {
	t.Helper()
	ctx := context.Background()
	if err := repo.SavePlan(ctx, &Plan{
		PlanID: id, Query: "q", Domain: "generic", ExecutionMode: mode, Version: 1,
		WorkflowDefinition: []byte(`{"spec":{"steps":[]}}`), Status: PlanStatusPending,
		OrgID: "org_1", TenantID: "tenant_1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SavePlan: %v", err)
	}
	if status != PlanStatusExecuting {
		return
	}
	var mark error
	if marked {
		mark = repo.MarkExecutingWithPendingBinding(ctx, id)
	} else {
		mark = repo.UpdatePlanStatusAtomic(ctx, id, PlanStatusPending, PlanStatusExecuting)
	}
	if mark != nil {
		t.Fatalf("mark executing: %v", mark)
	}
}

func TestThePlanWorkflowIsBoundOnceWhileExecuting(t *testing.T) {
	for name, newRepo := range bindingRepositories() {
		t.Run(name, func(t *testing.T) {
			repo := newRepo(t)
			ctx := context.Background()
			suffix := strings.ReplaceAll(t.Name(), "/", "_")

			// Marked executing: an empty binding, read back as marked.
			executing := "plan_bind_" + suffix
			savedPlan(t, repo, executing, PlanStatusExecuting)
			if got, _ := repo.GetPlan(ctx, executing); got.Status != PlanStatusExecuting {
				t.Fatalf("plan status = %s, want executing", got.Status)
			} else if id, marked := got.ExecutionBinding(); id != "" || !marked {
				t.Fatalf("a marked plan reads (%q, %v), want (\"\", true)", id, marked)
			}

			// The bind fills it, and it reads back.
			if err := repo.BindExecutionWorkflow(ctx, executing, "wf_real"); err != nil {
				t.Fatalf("bind: %v", err)
			}
			if got, _ := repo.GetPlan(ctx, executing); got.BoundWorkflowID() != "wf_real" {
				t.Errorf("bound workflow = %q, want wf_real", got.BoundWorkflowID())
			}

			// Once: a second bind is refused and the first stands.
			if err := repo.BindExecutionWorkflow(ctx, executing, "wf_lookalike"); !errors.Is(err, ErrPlanWorkflowBindRefused) {
				t.Errorf("rebind = %v, want ErrPlanWorkflowBindRefused", err)
			}
			if got, _ := repo.GetPlan(ctx, executing); got.BoundWorkflowID() != "wf_real" {
				t.Errorf("after a refused rebind the bound workflow = %q, want wf_real", got.BoundWorkflowID())
			}

			// Only a marked binding is filled: a pending plan, and a plan
			// executing with no binding (the pre-release shape), refuse.
			pending := "plan_bind_pending_" + suffix
			savedPlan(t, repo, pending, PlanStatusPending)
			if err := repo.BindExecutionWorkflow(ctx, pending, "wf_real"); !errors.Is(err, ErrPlanWorkflowBindRefused) {
				t.Errorf("bind of a pending plan = %v, want ErrPlanWorkflowBindRefused", err)
			}
			unmarked := "plan_bind_unmarked_" + suffix
			savedPlanInMode(t, repo, unmarked, PlanStatusExecuting, "confirm", false)
			if err := repo.BindExecutionWorkflow(ctx, unmarked, "wf_real"); !errors.Is(err, ErrPlanWorkflowBindRefused) {
				t.Errorf("bind of an unmarked executing plan = %v, want ErrPlanWorkflowBindRefused", err)
			}
			if got, _ := repo.GetPlan(ctx, unmarked); func() bool { _, m := got.ExecutionBinding(); return m }() {
				t.Errorf("an unmarked executing plan reads as marked")
			}

			// The executing mark with its binding moves only a pending plan.
			if err := repo.MarkExecutingWithPendingBinding(ctx, executing); !errors.Is(err, ErrPlanAlreadyRun) {
				t.Errorf("re-marking an executing plan = %v, want ErrPlanAlreadyRun", err)
			}

			// A plan that has ended reads unbound (its execution_result is its
			// result, not a binding).
			if err := repo.UpdatePlanStatus(ctx, executing, PlanStatusCompleted, []byte(`{"wcp_workflow_id":"wf_real"}`), ""); err != nil {
				t.Fatalf("complete: %v", err)
			}
			if got, _ := repo.GetPlan(ctx, executing); got.BoundWorkflowID() != "" {
				t.Errorf("a completed plan reads bound to %q, want unbound", got.BoundWorkflowID())
			}
		})
	}
}

// GetPlanForExecution marks a confirm or step plan executing WITH an empty
// binding, and any other mode without one.
func TestGetPlanForExecutionMarksConfirmAndStepPlansWithAnEmptyBinding(t *testing.T) {
	for name, newRepo := range bindingRepositories() {
		t.Run(name, func(t *testing.T) {
			repo := newRepo(t)
			svc := NewService(repo)
			ctx := context.Background()
			suffix := strings.ReplaceAll(t.Name(), "/", "_")
			for _, tc := range []struct {
				mode       string
				wantMarked bool
			}{{"confirm", true}, {"step", true}, {"auto", false}, {"sequential", false}} {
				id := "plan_mark_" + tc.mode + "_" + suffix
				savedPlanInMode(t, repo, id, PlanStatusPending, tc.mode, false)
				if _, err := svc.GetPlanForExecution(ctx, id, "org_1"); err != nil {
					t.Fatalf("%s: GetPlanForExecution: %v", tc.mode, err)
				}
				got, _ := repo.GetPlan(ctx, id)
				bound, marked := got.ExecutionBinding()
				if got.Status != PlanStatusExecuting || marked != tc.wantMarked || bound != "" {
					t.Errorf("%s: plan = %s binding (%q, %v), want executing with marked=%v and no id", tc.mode, got.Status, bound, marked, tc.wantMarked)
				}
			}
		})
	}
}

// modeChangingRepository answers GetPlan with the plan's mode as it was BEFORE
// an update landed, standing in for a mode changed between
// GetPlanForExecution's read and its mark.
type modeChangingRepository struct {
	Repository
	staleMode string
}

func (r *modeChangingRepository) GetPlan(ctx context.Context, planID string) (*Plan, error) {
	p, err := r.Repository.GetPlan(ctx, planID)
	if err != nil {
		return nil, err
	}
	stale := *p
	stale.ExecutionMode = r.staleMode
	return &stale, nil
}

// The marker follows the plan's STORED mode, not the mode the service read: a
// plan stored as confirm is marked even if GetPlanForExecution read it as auto,
// and a plan stored as auto is not marked even if read as confirm.
func TestTheExecutingMarkFollowsTheStoredModeNotTheOneRead(t *testing.T) {
	for name, newRepo := range bindingRepositories() {
		t.Run(name, func(t *testing.T) {
			repo := newRepo(t)
			ctx := context.Background()
			suffix := strings.ReplaceAll(t.Name(), "/", "_")
			for _, tc := range []struct {
				stored, read string
				wantMarked   bool
			}{
				{"confirm", "auto", true},
				{"auto", "confirm", false},
			} {
				id := "plan_mode_race_" + tc.stored + "_" + suffix
				savedPlanInMode(t, repo, id, PlanStatusPending, tc.stored, false)
				svc := NewService(&modeChangingRepository{Repository: repo, staleMode: tc.read})
				if _, err := svc.GetPlanForExecution(ctx, id, "org_1"); err != nil {
					t.Fatalf("stored %s read %s: GetPlanForExecution: %v", tc.stored, tc.read, err)
				}
				got, _ := repo.GetPlan(ctx, id)
				if _, marked := got.ExecutionBinding(); got.Status != PlanStatusExecuting || marked != tc.wantMarked {
					t.Errorf("stored %s read %s: plan %s marked=%v, want executing marked=%v", tc.stored, tc.read, got.Status, marked, tc.wantMarked)
				}
			}
		})
	}
}
