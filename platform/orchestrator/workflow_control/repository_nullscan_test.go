// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Real-PG regression guard for the approve/reject 500 fixed in WS-12 (#2778).
//
// The workflow scan (GetByID) read org_id/user_id/client_id and the step scan
// (scanWorkflowStepRow, via GetStep) read model/provider/step_name/step_type/
// decision_reason straight into Go strings. All of those columns are nullable —
// a langchain workflow registered without a user has NULL user_id, and a
// tool_call step legitimately has NULL model/provider. So approving such a step
// 500-ed with "converting NULL to string is unsupported". This inserts that
// exact NULL shape via raw SQL (repo.Create/AddStep would write empty strings,
// not NULL) and asserts both reads succeed. Runs against a real Postgres
// (testcontainers), the
// only harness that reproduces a genuine column-level NULL.
func TestPostgresRepository_NullColumns_Regression(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	tenantID := fmt.Sprintf("test-tenant-nullcol-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)
	wfID := fmt.Sprintf("wf_nullcol_%d", time.Now().UnixNano())

	// Workflow with NULL user_id/org_id/client_id (registered without a user).
	if _, err := db.ExecContext(ctx, `
		INSERT INTO workflows (workflow_id, workflow_name, source, status, total_steps, tenant_id, user_id, org_id, client_id)
		VALUES ($1, 'Null Col WF', 'langchain', 'in_progress', 1, $2, NULL, NULL, NULL)`,
		wfID, tenantID); err != nil {
		t.Fatalf("insert workflow: %v", err)
	}

	// tool_call step with NULL model/provider/step_name/step_type/decision_reason.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO workflow_steps (workflow_id, step_id, step_index, decision, approval_status, model, provider, step_name, step_type, decision_reason)
		VALUES ($1, 'null-step', 0, 'require_approval', 'pending', NULL, NULL, NULL, NULL, NULL)`,
		wfID); err != nil {
		t.Fatalf("insert step: %v", err)
	}

	// GetByID must not error on NULL identity columns (was the first approve 500).
	wf, err := repo.GetByID(ctx, wfID)
	if err != nil {
		t.Fatalf("GetByID with NULL user_id/org_id/client_id must not error (regression #2778): %v", err)
	}
	if wf.UserID != "" || wf.OrgID != "" || wf.ClientID != "" {
		t.Errorf("NULL identity columns should scan to empty strings, got user=%q org=%q client=%q",
			wf.UserID, wf.OrgID, wf.ClientID)
	}

	// GetStep must not error on NULL model/provider/etc. (the second approve 500).
	step, err := repo.GetStep(ctx, wfID, "null-step")
	if err != nil {
		t.Fatalf("GetStep with NULL model/provider must not error (regression #2778): %v", err)
	}
	if step.Model != "" || step.Provider != "" || step.StepName != "" || step.DecisionReason != "" {
		t.Errorf("NULL text columns should scan to empty strings, got model=%q provider=%q name=%q reason=%q",
			step.Model, step.Provider, step.StepName, step.DecisionReason)
	}

	// GetPendingApprovals backs the Approvals list page (GET
	// /api/v1/workflows/approvals/pending); it has its own inline scan of the
	// same nullable columns (step_name/step_type/decision_reason/step_input), so
	// a pending NULL-column step must not 500 the whole list. (Found by R3.)
	pending, err := repo.GetPendingApprovals(ctx, tenantID, 20)
	if err != nil {
		t.Fatalf("GetPendingApprovals with a NULL-column pending step must not error (regression #2778): %v", err)
	}
	found := false
	for _, p := range pending {
		if p.StepID == "null-step" {
			found = true
			if p.StepName != "" || p.DecisionReason != "" {
				t.Errorf("NULL columns should scan to empty strings, got name=%q reason=%q", p.StepName, p.DecisionReason)
			}
		}
	}
	if !found {
		t.Errorf("seeded pending NULL-column step not returned by GetPendingApprovals")
	}

	// GetPendingPlanApprovals (MAP plane, GET /api/v1/plans/approvals/pending)
	// has its own inline scan of the same nullable columns. Seed a plan_id
	// workflow + a NULL-column pending step and assert it survives the scan.
	planWfID := fmt.Sprintf("wf_nullcol_plan_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, `
		INSERT INTO workflows (workflow_id, workflow_name, source, status, total_steps, tenant_id, metadata)
		VALUES ($1, 'Null Col Plan WF', 'langchain', 'in_progress', 1, $2, '{"plan_id":"plan_ws12_nullcol"}'::jsonb)`,
		planWfID, tenantID); err != nil {
		t.Fatalf("insert plan workflow: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO workflow_steps (workflow_id, step_id, step_index, decision, approval_status, model, provider, step_name, step_type, decision_reason)
		VALUES ($1, 'plan-null-step', 0, 'require_approval', 'pending', NULL, NULL, NULL, NULL, NULL)`,
		planWfID); err != nil {
		t.Fatalf("insert plan step: %v", err)
	}
	planPending, err := repo.GetPendingPlanApprovals(ctx, tenantID, "", 20)
	if err != nil {
		t.Fatalf("GetPendingPlanApprovals with a NULL-column pending step must not error (regression #2778): %v", err)
	}
	planFound := false
	for _, p := range planPending {
		if p.StepID == "plan-null-step" {
			planFound = true
		}
	}
	if !planFound {
		t.Errorf("seeded pending NULL-column plan step not returned by GetPendingPlanApprovals")
	}
}
