// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Covers the plan-id lookup path used by MAP's plan-scoped HITL endpoints
// (Issue #1677 Phase 1) — mock repo lookup, service-layer tenant check,
// and error paths.

package workflow_control

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestMockRepository_GetByPlanID(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	wf1Meta, _ := json.Marshal(map[string]interface{}{"plan_id": "plan-42", "execution_mode": "confirm"})
	wf1 := &Workflow{
		WorkflowID: "wf1", WorkflowName: "map-confirm-plan-42",
		TenantID: "tenant-A", OrgID: "org-A", Metadata: wf1Meta,
	}
	if err := repo.Create(ctx, wf1); err != nil {
		t.Fatalf("Create wf1: %v", err)
	}

	got, err := repo.GetByPlanID(ctx, "plan-42")
	if err != nil {
		t.Fatalf("GetByPlanID(plan-42): %v", err)
	}
	if got.WorkflowID != "wf1" {
		t.Errorf("WorkflowID = %q, want wf1", got.WorkflowID)
	}

	// Unknown plan → ErrWorkflowNotFound
	_, err = repo.GetByPlanID(ctx, "no-such-plan")
	if !errors.Is(err, ErrWorkflowNotFound) {
		t.Errorf("err = %v, want ErrWorkflowNotFound", err)
	}
}

func TestMockRepository_GetByPlanID_PicksMostRecent(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Two workflows with the same plan_id (shouldn't happen in production, but
	// the lookup must still produce a deterministic winner — latest created).
	meta, _ := json.Marshal(map[string]interface{}{"plan_id": "plan-shared"})
	old := &Workflow{WorkflowID: "wf-old", WorkflowName: "old", Metadata: meta}
	if err := repo.Create(ctx, old); err != nil {
		t.Fatalf("Create old: %v", err)
	}

	// Force a small time gap so CreatedAt ordering is deterministic on
	// fast machines.
	time.Sleep(2 * time.Millisecond)

	newer := &Workflow{WorkflowID: "wf-new", WorkflowName: "new", Metadata: meta}
	if err := repo.Create(ctx, newer); err != nil {
		t.Fatalf("Create newer: %v", err)
	}

	got, err := repo.GetByPlanID(ctx, "plan-shared")
	if err != nil {
		t.Fatalf("GetByPlanID: %v", err)
	}
	if got.WorkflowID != "wf-new" {
		t.Errorf("GetByPlanID picked %q, want wf-new (most recently created)", got.WorkflowID)
	}
}

func TestMockRepository_GetByPlanID_MetadataWithoutPlanID(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	wf := &Workflow{
		WorkflowID:   "wf",
		Metadata:     json.RawMessage(`{"some_other_key": "value"}`),
	}
	if err := repo.Create(ctx, wf); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err := repo.GetByPlanID(ctx, "plan-x")
	if !errors.Is(err, ErrWorkflowNotFound) {
		t.Errorf("err = %v, want ErrWorkflowNotFound when metadata has no plan_id", err)
	}
}

func TestMockRepository_GetByPlanID_NilMetadata(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	if err := repo.Create(ctx, &Workflow{WorkflowID: "wf-nil-meta"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err := repo.GetByPlanID(ctx, "plan-x")
	if !errors.Is(err, ErrWorkflowNotFound) {
		t.Errorf("err = %v, want ErrWorkflowNotFound when metadata is nil", err)
	}
}

// TestService_GetWorkflowByPlanID asserts tenant isolation — a caller from a
// different tenant / org must receive ErrWorkflowNotFound, not the real data
// (prevents tenant-existence side-channel leaks).
func TestService_GetWorkflowByPlanID(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	meta, _ := json.Marshal(map[string]interface{}{"plan_id": "plan-tenant"})
	wf := &Workflow{
		WorkflowID: "wf", Metadata: meta,
		TenantID: "tenant-A", OrgID: "org-A",
	}
	if err := repo.Create(ctx, wf); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.GetWorkflowByPlanID(ctx, "plan-tenant", "tenant-A", "org-A")
	if err != nil {
		t.Fatalf("same-tenant lookup: %v", err)
	}
	if got.WorkflowID != "wf" {
		t.Errorf("WorkflowID = %q, want wf", got.WorkflowID)
	}

	// Foreign tenant → NotFound (not a different error type — side-channel
	// protection).
	_, err = svc.GetWorkflowByPlanID(ctx, "plan-tenant", "tenant-B", "org-B")
	if !errors.Is(err, ErrWorkflowNotFound) {
		t.Errorf("foreign tenant: err = %v, want ErrWorkflowNotFound", err)
	}

	// Community mode / internal service callers pass empty strings → bypass.
	got, err = svc.GetWorkflowByPlanID(ctx, "plan-tenant", "", "")
	if err != nil {
		t.Fatalf("empty-tenant bypass: %v", err)
	}
	if got == nil {
		t.Error("empty-tenant bypass should return workflow, got nil")
	}
}

func TestService_GetStep_TenantIsolation(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	ctx := context.Background()

	wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "isolate"},
		"tenant-A", "org-A", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	if _, err := svc.StepGate(ctx, wf.WorkflowID, "s1",
		&StepGateRequest{StepName: "s1", StepType: StepTypeLLMCall},
		"tenant-A", "org-A", "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate: %v", err)
	}

	// Owner can fetch.
	step, err := svc.GetStep(ctx, wf.WorkflowID, "s1", "tenant-A", "org-A")
	if err != nil {
		t.Fatalf("owner GetStep: %v", err)
	}
	if step.StepID != "s1" {
		t.Errorf("StepID = %q, want s1", step.StepID)
	}

	// Foreign tenant receives NotFound (no step identity leaked).
	_, err = svc.GetStep(ctx, wf.WorkflowID, "s1", "tenant-B", "org-B")
	if !errors.Is(err, ErrWorkflowNotFound) {
		t.Errorf("foreign tenant: err = %v, want ErrWorkflowNotFound", err)
	}
}
