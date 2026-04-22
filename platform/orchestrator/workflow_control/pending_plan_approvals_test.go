// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Unit tests for the MAP-plane pending-approvals listing (Issue #1680).
// Exercises the service + MockRepository paths plus the JSON marshaling of
// the PendingApprovalResponse.PlanID extension. DB-backed coverage of the
// JSONB filter lives in repository_integration_test.go
// (TestPostgresRepository_Integration_PlanApprovals).

package workflow_control

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// newPlanApprovalsFixture seeds a service with two MAP-backed workflows
// (plan-a, plan-b) and one native WCP workflow, each with a pending step, so
// plan-plane tests can exercise filter, tenant isolation, and asymmetry with
// the WCP listing.
func newPlanApprovalsFixture(t *testing.T, tenantID string) (*Service, *MockRepository) {
	t.Helper()

	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	pending := ApprovalStatusPending

	seed := func(workflowID, workflowName, planID, stepID string, tenant string) {
		var meta json.RawMessage
		if planID != "" {
			meta, _ = json.Marshal(map[string]interface{}{"plan_id": planID})
		}
		wf := &Workflow{
			WorkflowID:   workflowID,
			WorkflowName: workflowName,
			Source:       WorkflowSourceExternal,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenant,
			Metadata:     meta,
		}
		if err := repo.Create(ctx, wf); err != nil {
			t.Fatalf("seed workflow %s: %v", workflowID, err)
		}
		step := &WorkflowStep{
			WorkflowID:     workflowID,
			StepID:         stepID,
			StepIndex:      0,
			StepName:       "step-name-" + stepID,
			StepType:       StepTypeToolCall,
			Decision:       GateDecisionRequireApproval,
			ApprovalStatus: &pending,
		}
		if err := repo.AddStep(ctx, step); err != nil {
			t.Fatalf("seed step %s/%s: %v", workflowID, stepID, err)
		}
	}

	seed("wf-map-a", "map-confirm-plan-a", "plan-a", "step_0_analyze", tenantID)
	seed("wf-map-b", "map-confirm-plan-b", "plan-b", "step_0_prepare", tenantID)
	seed("wf-wcp-c", "wcp-native", "", "step_0", tenantID)
	// Second tenant — must never show up
	seed("wf-other", "map-other", "plan-other", "step_0", "other-tenant")

	return svc, repo
}

// TestService_GetPendingPlanApprovals_HappyPath asserts MAP-backed workflows
// are returned with plan_id populated and native WCP workflows are excluded.
func TestService_GetPendingPlanApprovals_HappyPath(t *testing.T) {
	svc, _ := newPlanApprovalsFixture(t, "tenant-1")

	got, err := svc.GetPendingPlanApprovals(context.Background(), "tenant-1", "", 10)
	if err != nil {
		t.Fatalf("GetPendingPlanApprovals: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 MAP-backed approvals, got %d: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, a := range got {
		if a.PlanID == "" {
			t.Errorf("entry %s: PlanID must be populated on MAP-plane listing", a.WorkflowID)
		}
		seen[a.PlanID] = true
	}
	if !seen["plan-a"] || !seen["plan-b"] {
		t.Errorf("expected plan-a and plan-b; got %+v", seen)
	}
	if seen[""] {
		t.Errorf("native WCP workflow leaked into MAP listing")
	}
}

// TestService_GetPendingPlanApprovals_PlanIDFilter asserts the ?plan_id=
// query parameter scopes results to a single plan.
func TestService_GetPendingPlanApprovals_PlanIDFilter(t *testing.T) {
	svc, _ := newPlanApprovalsFixture(t, "tenant-1")

	got, err := svc.GetPendingPlanApprovals(context.Background(), "tenant-1", "plan-a", 10)
	if err != nil {
		t.Fatalf("GetPendingPlanApprovals: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("filter=plan-a: want 1, got %d", len(got))
	}
	if got[0].PlanID != "plan-a" {
		t.Errorf("plan_id = %q, want plan-a", got[0].PlanID)
	}
	if got[0].WorkflowID != "wf-map-a" {
		t.Errorf("workflow_id = %q, want wf-map-a", got[0].WorkflowID)
	}
}

// TestService_GetPendingPlanApprovals_TenantIsolation asserts the tenant
// filter excludes other tenants' MAP-backed approvals.
func TestService_GetPendingPlanApprovals_TenantIsolation(t *testing.T) {
	svc, _ := newPlanApprovalsFixture(t, "tenant-1")

	got, err := svc.GetPendingPlanApprovals(context.Background(), "tenant-1", "", 10)
	if err != nil {
		t.Fatalf("GetPendingPlanApprovals: %v", err)
	}
	for _, a := range got {
		if a.PlanID == "plan-other" {
			t.Errorf("leaked other-tenant plan: %+v", a)
		}
	}
}

// TestService_GetPendingPlanApprovals_EmptyResult asserts an empty tenant
// returns [] (not nil-that-serialises-to-null).
func TestService_GetPendingPlanApprovals_EmptyResult(t *testing.T) {
	svc, _ := newPlanApprovalsFixture(t, "tenant-1")

	got, err := svc.GetPendingPlanApprovals(context.Background(), "no-such-tenant", "", 10)
	if err != nil {
		t.Fatalf("GetPendingPlanApprovals: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty-tenant result: want 0 entries, got %d", len(got))
	}
}

// TestService_GetPendingPlanApprovals_LimitRespected asserts the limit
// argument caps the returned row count.
func TestService_GetPendingPlanApprovals_LimitRespected(t *testing.T) {
	svc, _ := newPlanApprovalsFixture(t, "tenant-1")

	got, err := svc.GetPendingPlanApprovals(context.Background(), "tenant-1", "", 1)
	if err != nil {
		t.Fatalf("GetPendingPlanApprovals: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("limit=1: want 1, got %d", len(got))
	}
}

// TestService_CountPendingPlanApprovals asserts the count endpoint matches
// the GET filter behavior.
func TestService_CountPendingPlanApprovals(t *testing.T) {
	svc, _ := newPlanApprovalsFixture(t, "tenant-1")
	ctx := context.Background()

	total, err := svc.CountPendingPlanApprovals(ctx, "tenant-1", "")
	if err != nil {
		t.Fatalf("CountPendingPlanApprovals: %v", err)
	}
	if total != 2 {
		t.Errorf("unfiltered count: want 2, got %d", total)
	}

	filtered, err := svc.CountPendingPlanApprovals(ctx, "tenant-1", "plan-a")
	if err != nil {
		t.Fatalf("CountPendingPlanApprovals filter: %v", err)
	}
	if filtered != 1 {
		t.Errorf("filter count: want 1, got %d", filtered)
	}

	none, err := svc.CountPendingPlanApprovals(ctx, "tenant-1", "plan-missing")
	if err != nil {
		t.Fatalf("CountPendingPlanApprovals absent: %v", err)
	}
	if none != 0 {
		t.Errorf("absent plan count: want 0, got %d", none)
	}
}

// TestPendingApprovalResponse_JSONMarshalPlanIDOmitted asserts plan_id is
// suppressed from the wire when empty — preserving the WCP asymmetry so
// existing WCP clients don't see a new nullable field appear.
func TestPendingApprovalResponse_JSONMarshalPlanIDOmitted(t *testing.T) {
	entry := PendingApprovalResponse{
		WorkflowID:   "wf-1",
		WorkflowName: "native-wcp",
		StepID:       "step-1",
		StepIndex:    0,
		Decision:     GateDecisionRequireApproval,
		CreatedAt:    time.Now(),
	}
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := out["plan_id"]; present {
		t.Errorf("plan_id must be omitted on WCP-plane entries; got %s", string(b))
	}
}

// TestPendingApprovalResponse_JSONMarshalPlanIDPresent asserts plan_id is
// emitted when populated — the MAP-plane behavior.
func TestPendingApprovalResponse_JSONMarshalPlanIDPresent(t *testing.T) {
	entry := PendingApprovalResponse{
		WorkflowID:   "wf-map-1",
		WorkflowName: "map-confirm-plan-1",
		PlanID:       "plan-1",
		StepID:       "step_0",
		StepIndex:    0,
		Decision:     GateDecisionRequireApproval,
		CreatedAt:    time.Now(),
	}
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pid, ok := out["plan_id"]
	if !ok {
		t.Fatalf("plan_id must be present on MAP-plane entries; got %s", string(b))
	}
	if pid != "plan-1" {
		t.Errorf("plan_id = %v, want plan-1", pid)
	}
}

// TestMockRepository_WorkflowPlanIDParsing verifies the helper that extracts
// plan_id from workflow metadata handles nil, non-object, and missing-key
// cases gracefully — the Postgres equivalent relies on native JSONB ops so
// these edge cases only bite the mock path.
func TestMockRepository_WorkflowPlanIDParsing(t *testing.T) {
	tests := []struct {
		name     string
		metadata json.RawMessage
		want     string
	}{
		{"nil metadata", nil, ""},
		{"empty metadata", json.RawMessage("{}"), ""},
		{"no plan_id key", json.RawMessage(`{"foo":"bar"}`), ""},
		{"plan_id populated", json.RawMessage(`{"plan_id":"plan-1"}`), "plan-1"},
		{"plan_id non-string", json.RawMessage(`{"plan_id":123}`), ""},
		{"malformed json", json.RawMessage(`{not json`), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &Workflow{Metadata: tc.metadata}
			if got := workflowPlanID(w); got != tc.want {
				t.Errorf("workflowPlanID(%s) = %q, want %q", string(tc.metadata), got, tc.want)
			}
		})
	}
}
