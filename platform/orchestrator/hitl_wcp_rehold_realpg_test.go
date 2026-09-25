// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-PostgreSQL proof, across the orchestrator's own wiring, that a workflow
// step held again after its earlier hold was approved is governed by its NEW
// hold (#4249 row 5700138809): the WCP adapter writes the new row, the
// workflow plane's approval reads the new row's expiry and resolves the new
// row, and the approved first hold is left exactly as it was.
//
// Every piece is the production one except the workflow repository (the
// in-memory MockRepository) and the gate's policy decision (a gate override
// holds the step); the adapter is called directly where the gate would call it.
//
// Gating: TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).

package orchestrator

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/hitl/queue"
	"axonflow/platform/agent/rls"
	"axonflow/platform/orchestrator/workflow_control"
)

func TestReHeldStepIsApprovedOnItsOwnHold_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	db, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app-role DSN: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	approletest.AssertCurrentUser(t, db, "axonflow_app_role")

	const (
		org    = "rehold-org"
		tenant = "rehold-tenant"
		step   = "step-a"
	)
	ctx := context.Background()

	enq := queue.NewEnqueuer(db, queue.Config{Plane: wcpHITLRequestType, DefaultExpiry: 24 * time.Hour})
	enq.SetTierProviderForTest(entitledTier)
	adapter := newWCPHITLAdapter(enq)

	repo := workflow_control.NewMockRepository()
	svc := workflow_control.NewService(repo, &wcpParityPolicyEvaluator{}, nil)
	svc.SetHITLMirrorResolver(&wcpHITLMirrorResolver{db: db})

	wf, err := svc.CreateWorkflow(ctx, &workflow_control.CreateWorkflowRequest{WorkflowName: "rehold"}, tenant, org, "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	requireApproval := workflow_control.GateDecisionRequireApproval
	if _, err := svc.StepGate(ctx, wf.WorkflowID, step,
		&workflow_control.StepGateRequest{StepName: step, StepType: workflow_control.StepTypeToolCall, GateOverride: &requireApproval},
		tenant, org, "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate: %v", err)
	}

	hold := func(expiresAt time.Time) *HITLApprovalResponse {
		t.Helper()
		resp, err := adapter.CreateApproval(ctx, &HITLApprovalRequest{
			OrgID: org, TenantID: tenant, ClientID: "client-1", UserID: "user-1",
			ExecutionID: wf.WorkflowID, StepName: step, StepType: "tool_call",
			PolicyID: "pol-1", PolicyName: "hold policy", TriggerReason: "requires approval", Severity: "high",
			RequestContext: map[string]interface{}{"workflow_id": wf.WorkflowID, "step_id": step},
			ExpiresAt:      expiresAt,
		})
		if err != nil {
			t.Fatalf("CreateApproval: %v", err)
		}
		return resp
	}
	rowJSON := func(id uuid.UUID) string {
		t.Helper()
		var s string
		if err := rls.WithOrgScope(ctx, db, org, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT to_jsonb(q)::text FROM hitl_approval_queue q WHERE request_id = $1`, id).Scan(&s)
		}); err != nil {
			t.Fatalf("read row %s: %v", id, err)
		}
		return s
	}
	hold1 := uuid.MustParse(workflow_control.DeriveHITLApprovalIDForHold(wf.WorkflowID, step, 1))
	hold2 := uuid.MustParse(workflow_control.DeriveHITLApprovalIDForHold(wf.WorkflowID, step, 2))

	// Hold 1, with a window short enough to pass before the re-hold is approved.
	first := hold(time.Now().Add(2 * time.Second))
	if first.ApprovalID != hold1 || first.Enqueue != string(queue.OutcomeCreated) {
		t.Fatalf("hold 1: id %s enqueue %q, want %s created", first.ApprovalID, first.Enqueue, hold1)
	}
	if err := svc.ApproveStep(ctx, wf.WorkflowID, step, tenant, org, "first@example.com", "approved within its window"); err != nil {
		t.Fatalf("approve hold 1: %v", err)
	}
	approvedFirst := rowJSON(hold1)
	time.Sleep(2500 * time.Millisecond)

	// The step is held again: its gate is evaluated once more and holds it (the
	// re-evaluation an approved step admits), writing a pending step row.
	if _, err := svc.StepGate(ctx, wf.WorkflowID, step,
		&workflow_control.StepGateRequest{StepName: step, StepType: workflow_control.StepTypeToolCall, GateOverride: &requireApproval},
		tenant, org, "user-1", "client-1"); err != nil {
		t.Fatalf("re-gate the approved step: %v", err)
	}
	second := hold(time.Now().Add(time.Hour))
	if second.ApprovalID != hold2 || second.Enqueue != string(queue.OutcomeCreated) {
		t.Fatalf("re-hold: id %s enqueue %q, want hold 2 %s created", second.ApprovalID, second.Enqueue, hold2)
	}
	if got := svc.CurrentApprovalID(ctx, wf.WorkflowID, step, tenant, org); got != hold2.String() {
		t.Errorf("CurrentApprovalID = %s, want hold 2 %s", got, hold2)
	}

	// Hold 1's window has passed; hold 2's has not. The approval is judged by
	// the hold it decides.
	if err := svc.ApproveStep(ctx, wf.WorkflowID, step, tenant, org, "second@example.com", "approved the re-hold"); err != nil {
		t.Fatalf("approve the re-held step: %v (an expiry read from the first hold refuses it)", err)
	}

	var status, reviewer string
	if err := rls.WithOrgScope(ctx, db, org, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT status, COALESCE(reviewer_email, '') FROM hitl_approval_queue WHERE request_id = $1`, hold2).Scan(&status, &reviewer)
	}); err != nil {
		t.Fatalf("read hold 2: %v", err)
	}
	if status != "approved" || reviewer != "second@example.com" {
		t.Errorf("hold 2 = %s by %q, want approved by second@example.com", status, reviewer)
	}
	// The whole row, updated_at included: the re-hold and its approval never
	// touched hold 1.
	if after := rowJSON(hold1); after != approvedFirst {
		t.Errorf("hold 1 changed after the re-hold was approved:\nbefore %s\nafter  %s", approvedFirst, after)
	}

	var created string
	if err := rls.WithOrgScope(ctx, db, org, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) || '|' || string_agg(COALESCE(previous_status, '<null>') || ':' || COALESCE(new_status, '<null>'), ',')
			FROM hitl_approval_history WHERE request_id = $1 AND action = 'created'`, hold2).Scan(&created)
	}); err != nil {
		t.Fatalf("read hold 2's history: %v", err)
	}
	if created != "1|approved:pending" {
		t.Errorf("hold 2's created history = %q, want one row with previous_status approved (1|approved:pending)", created)
	}
}

// holdFixture is the production adapter, mirror and Service over a real
// app-role pool. t is the test (or subtest) whose failures its helpers report;
// a subtest sets it first.
type holdFixture struct {
	t       *testing.T
	ctx     context.Context
	db      *sql.DB
	adapter *wcpHITLAdapter
	repo    *workflow_control.MockRepository
	svc     *workflow_control.Service
}

const (
	holdOrg    = "rehold-org"
	holdTenant = "rehold-tenant"
)

func newHoldFixture(t *testing.T) *holdFixture {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	db, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app-role DSN: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	approletest.AssertCurrentUser(t, db, "axonflow_app_role")

	enq := queue.NewEnqueuer(db, queue.Config{Plane: wcpHITLRequestType, DefaultExpiry: 24 * time.Hour})
	enq.SetTierProviderForTest(entitledTier)
	repo := workflow_control.NewMockRepository()
	svc := workflow_control.NewService(repo, &wcpParityPolicyEvaluator{}, nil)
	svc.SetHITLMirrorResolver(&wcpHITLMirrorResolver{db: db})
	return &holdFixture{t: t, ctx: context.Background(), db: db, adapter: newWCPHITLAdapter(enq), repo: repo, svc: svc}
}

// gate creates a workflow, gates step to require_approval, and holds it with
// the given approval expiry. It returns the workflow id and hold 1's id.
func (f *holdFixture) gate(name, step string, expiresAt time.Time) (string, uuid.UUID) {
	f.t.Helper()
	wf, err := f.svc.CreateWorkflow(f.ctx, &workflow_control.CreateWorkflowRequest{WorkflowName: name}, holdTenant, holdOrg, "user-1", "client-1")
	if err != nil {
		f.t.Fatalf("CreateWorkflow: %v", err)
	}
	requireApproval := workflow_control.GateDecisionRequireApproval
	if _, err := f.svc.StepGate(f.ctx, wf.WorkflowID, step,
		&workflow_control.StepGateRequest{StepName: step, StepType: workflow_control.StepTypeToolCall, GateOverride: &requireApproval},
		holdTenant, holdOrg, "user-1", "client-1"); err != nil {
		f.t.Fatalf("StepGate: %v", err)
	}
	resp, err := f.adapter.CreateApproval(f.ctx, &HITLApprovalRequest{
		OrgID: holdOrg, TenantID: holdTenant, ClientID: "client-1", UserID: "user-1",
		ExecutionID: wf.WorkflowID, StepName: step, StepType: "tool_call",
		PolicyID: "pol-1", PolicyName: "hold policy", TriggerReason: "requires approval", Severity: "high",
		RequestContext: map[string]interface{}{"workflow_id": wf.WorkflowID, "step_id": step},
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		f.t.Fatalf("CreateApproval: %v", err)
	}
	return wf.WorkflowID, resp.ApprovalID
}

// inject writes a pending wcp_step_gate row that NAMES the step but is not one
// of its hold ids, through the plain insert the agent's decide-plane create
// used (a fresh uuid.New() id) - the row a client could write before the type
// was reserved.
func (f *holdFixture) inject(workflowID, step string, expiresAt time.Time) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	if _, _, _, err := queue.Insert(f.ctx, f.db, queue.Params{
		RequestID: id, OrgID: holdOrg, TenantID: holdTenant, ClientID: "client-1", UserID: "user-1",
		OriginalQuery: step, RequestType: queue.RequestTypeWCPStepGate,
		RequestContext:    map[string]interface{}{"workflow_id": workflowID, "step_id": step},
		TriggeredPolicyID: "pol-x", TriggeredPolicyName: "injected", TriggerReason: "injected", Severity: "high",
		Status: "pending", ExpiresAt: expiresAt,
	}); err != nil {
		f.t.Fatalf("inject: %v", err)
	}
	return id
}

func (f *holdFixture) status(id uuid.UUID) string {
	f.t.Helper()
	var s string
	if err := rls.WithOrgScope(f.ctx, f.db, holdOrg, func(tx *sql.Tx) error {
		return tx.QueryRowContext(f.ctx, `SELECT status FROM hitl_approval_queue WHERE request_id = $1`, id).Scan(&s)
	}); err != nil {
		f.t.Fatalf("read %s: %v", id, err)
	}
	return s
}

// TestARowThatOnlyNamesTheStepGovernsNothing_RealPostgres is R3 round 1's
// PERMISSIVE finding, end to end: a pending wcp_step_gate row that names a held
// step under a non-hold id, with a far later expiry, must not become the hold
// the workflow plane reads. The expiry an approval is judged by, the row the
// approval resolves and the approval_id it projects are all the real hold's.
func TestARowThatOnlyNamesTheStepGovernsNothing_RealPostgres(t *testing.T) {
	f := newHoldFixture(t)
	const step = "step-a"

	t.Run("a lapsed hold is still refused", func(t *testing.T) {
		f.t = t
		wfID, hold1 := f.gate("injected-lapsed", step, time.Now().Add(2*time.Second))
		injected := f.inject(wfID, step, time.Now().Add(30*24*time.Hour))
		time.Sleep(2500 * time.Millisecond)

		err := f.svc.ApproveStep(f.ctx, wfID, step, holdTenant, holdOrg, "approver@example.com", "approving after the window")
		if !errors.Is(err, workflow_control.ErrApprovalExpired) {
			t.Errorf("approve after hold 1's window: err=%v, want ErrApprovalExpired (judged by the injected row's 30-day expiry)", err)
		}
		if s := f.status(hold1); s != "pending" {
			t.Errorf("hold 1 status = %s, want pending (the refused approval wrote nothing)", s)
		}
		if s := f.status(injected); s != "pending" {
			t.Errorf("injected row status = %s, want pending (untouched)", s)
		}
	})

	t.Run("an approval resolves and projects the real hold", func(t *testing.T) {
		f.t = t
		wfID, hold1 := f.gate("injected-live", step, time.Now().Add(time.Hour))
		injected := f.inject(wfID, step, time.Now().Add(30*24*time.Hour))

		if err := f.svc.ApproveStep(f.ctx, wfID, step, holdTenant, holdOrg, "approver@example.com", "approving within the window"); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if s := f.status(hold1); s != "approved" {
			t.Errorf("hold 1 status = %s, want approved", s)
		}
		if s := f.status(injected); s != "pending" {
			t.Errorf("injected row status = %s, want pending (the approval resolved it instead of the hold)", s)
		}
		if got := f.svc.CurrentApprovalID(f.ctx, wfID, step, holdTenant, holdOrg); got != hold1.String() {
			t.Errorf("approval_id = %s, want hold 1 %s", got, hold1)
		}
	})
}

// TestAnApprovalWithNoPendingHoldIsNotPending_RealPostgres: a step pending on
// the workflow plane whose newest hold is already decided (its re-hold was
// never written) is refused as not pending. The decided hold's window is
// never what an approval is judged by.
func TestAnApprovalWithNoPendingHoldIsNotPending_RealPostgres(t *testing.T) {
	f := newHoldFixture(t)
	const step = "step-a"
	wfID, hold1 := f.gate("decided-newest", step, time.Now().Add(time.Hour))
	if err := f.svc.ApproveStep(f.ctx, wfID, step, holdTenant, holdOrg, "first@example.com", "approved within its window"); err != nil {
		t.Fatalf("approve hold 1: %v", err)
	}
	// The step is held again, but its new hold is never queued (the adapter is
	// not called: the gate's enqueue failed).
	requireApproval := workflow_control.GateDecisionRequireApproval
	if _, err := f.svc.StepGate(f.ctx, wfID, step,
		&workflow_control.StepGateRequest{StepName: step, StepType: workflow_control.StepTypeToolCall, GateOverride: &requireApproval},
		holdTenant, holdOrg, "user-1", "client-1"); err != nil {
		t.Fatalf("re-gate the approved step: %v", err)
	}

	err := f.svc.ApproveStep(f.ctx, wfID, step, holdTenant, holdOrg, "second@example.com", "approving with no live hold")
	if !errors.Is(err, workflow_control.ErrApprovalHoldDecided) || !strings.Contains(err.Error(), "not pending") {
		t.Errorf("approve with no pending hold: err=%v, want a not-pending refusal wrapping ErrApprovalHoldDecided", err)
	}
	if s := f.status(hold1); s != "approved" {
		t.Errorf("hold 1 status = %s, want approved (unchanged)", s)
	}
}

// TestAPendingStrayWithNoHoldRefusesTheApproval_RealPostgres: a step held by
// its gate whose first hold was refused because a pending wcp_step_gate row
// names it outside its hold ids has no hold. Its approval must refuse
// fail-closed (ErrApprovalStateUnreadable) rather than read "no expiry declared"
// and be granted after the hold's deadline (#4249 row 5700138809, R3 round 2
// N1). Once the stray is decided the step has no live row, and the approval
// proceeds as for any step with no queue row.
func TestAPendingStrayWithNoHoldRefusesTheApproval_RealPostgres(t *testing.T) {
	f := newHoldFixture(t)
	const step = "step-a"
	wf, err := f.svc.CreateWorkflow(f.ctx, &workflow_control.CreateWorkflowRequest{WorkflowName: "stray-no-hold"}, holdTenant, holdOrg, "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	requireApproval := workflow_control.GateDecisionRequireApproval
	if _, err := f.svc.StepGate(f.ctx, wf.WorkflowID, step,
		&workflow_control.StepGateRequest{StepName: step, StepType: workflow_control.StepTypeToolCall, GateOverride: &requireApproval},
		holdTenant, holdOrg, "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate: %v", err)
	}
	stray := f.inject(wf.WorkflowID, step, time.Now().Add(30*24*time.Hour))
	resp, err := f.adapter.CreateApproval(f.ctx, &HITLApprovalRequest{
		OrgID: holdOrg, TenantID: holdTenant, ClientID: "client-1", UserID: "user-1",
		ExecutionID: wf.WorkflowID, StepName: step, StepType: "tool_call",
		PolicyID: "pol-1", PolicyName: "hold policy", TriggerReason: "requires approval", Severity: "high",
		RequestContext: map[string]interface{}{"workflow_id": wf.WorkflowID, "step_id": step},
	})
	if !errors.Is(err, queue.ErrHoldUnnamedRow) {
		t.Fatalf("precondition: hold 1 refused by the stray, got resp=%+v err=%v", resp, err)
	}

	err = f.svc.ApproveStep(f.ctx, wf.WorkflowID, step, holdTenant, holdOrg, "approver@example.com", "approving a step whose hold was refused")
	if !errors.Is(err, workflow_control.ErrApprovalStateUnreadable) {
		t.Errorf("approve with a pending stray and no hold: err=%v, want ErrApprovalStateUnreadable (fail-closed)", err)
	}
	if s := f.status(stray); s != "pending" {
		t.Errorf("stray status = %s, want pending (untouched)", s)
	}

	if err := queue.ResolveMirror(f.ctx, f.db, queue.StatusParams{
		OrgID: holdOrg, RequestID: stray, Status: "rejected",
		ReviewerID: "ops@example.com", ReviewerEmail: "ops@example.com", ReviewerRole: "workflow_approver",
		Comment: "clearing the stray row",
	}, holdTenant); err != nil {
		t.Fatalf("decide the stray: %v", err)
	}
	if err := f.svc.ApproveStep(f.ctx, wf.WorkflowID, step, holdTenant, holdOrg, "approver@example.com", "approving once the stray is decided"); err != nil {
		t.Errorf("approve once the stray is decided: %v, want it approved (no live row, no expiry declared)", err)
	}
}
