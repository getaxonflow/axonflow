// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"encoding/json"
	"testing"
)

// --- Checkpoint creation tests ---

func TestStepGate_CreatesCheckpoint(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Call StepGate
	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	// Verify checkpoint was created
	checkpoints, err := repo.ListCheckpoints(ctx, workflowID)
	if err != nil {
		t.Fatalf("ListCheckpoints failed: %v", err)
	}
	if len(checkpoints) != 1 {
		t.Fatalf("expected 1 checkpoint, got %d", len(checkpoints))
	}

	cp := checkpoints[0]
	if cp.StepID != "step-1" {
		t.Errorf("expected step-1, got %s", cp.StepID)
	}
	if cp.CheckpointType != CheckpointStepGate {
		t.Errorf("expected step_gate, got %s", cp.CheckpointType)
	}
	if cp.GateDecision != "allow" {
		t.Errorf("expected allow, got %s", cp.GateDecision)
	}
	if !cp.IsResumable {
		t.Error("allow decision should be resumable")
	}
}

func TestStepGate_BlockedStepCreatesNonResumableCheckpoint(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionBlock, reason: "blocked"}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	checkpoints, _ := repo.ListCheckpoints(ctx, workflowID)
	if len(checkpoints) != 1 {
		t.Fatalf("expected 1 checkpoint, got %d", len(checkpoints))
	}

	if checkpoints[0].IsResumable {
		t.Error("blocked step should NOT be resumable")
	}
}

func TestStepGate_RequireApprovalCreatesApprovalBoundaryCheckpoint(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionRequireApproval, reason: "needs approval"}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	checkpoints, _ := repo.ListCheckpoints(ctx, workflowID)
	if len(checkpoints) != 1 {
		t.Fatalf("expected 1 checkpoint, got %d", len(checkpoints))
	}

	cp := checkpoints[0]
	if cp.CheckpointType != CheckpointApprovalBoundary {
		t.Errorf("expected approval_boundary, got %s", cp.CheckpointType)
	}
	if !cp.IsResumable {
		t.Error("require_approval should be resumable")
	}
}

func TestStepGate_MultipleStepsCreateMultipleCheckpoints(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Create 3 step gates
	for _, stepID := range []string{"step-1", "step-2", "step-3"} {
		_, err := svc.StepGate(ctx, workflowID, stepID, &StepGateRequest{
			StepType: StepTypeToolCall,
		}, "tenant-1", "org-1", "user-1", "client-1")
		if err != nil {
			t.Fatalf("StepGate for %s failed: %v", stepID, err)
		}
	}

	checkpoints, _ := repo.ListCheckpoints(ctx, workflowID)
	if len(checkpoints) != 3 {
		t.Fatalf("expected 3 checkpoints, got %d", len(checkpoints))
	}

	// Verify ordering by step_index
	for i := 1; i < len(checkpoints); i++ {
		if checkpoints[i].StepIndex <= checkpoints[i-1].StepIndex {
			t.Errorf("checkpoints not ordered by step_index: %d <= %d",
				checkpoints[i].StepIndex, checkpoints[i-1].StepIndex)
		}
	}
}

func TestStepGate_ReevaluateUpdatesCheckpoint(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First gate
	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}

	// Re-evaluate same step
	_, err = svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType:    StepTypeToolCall,
		RetryPolicy: RetryPolicyReevaluate,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("reevaluate StepGate failed: %v", err)
	}

	// Should still be 1 checkpoint (upserted)
	checkpoints, _ := repo.ListCheckpoints(ctx, workflowID)
	if len(checkpoints) != 1 {
		t.Fatalf("expected 1 checkpoint after upsert, got %d", len(checkpoints))
	}
}

// --- GetCheckpoints tests ---

func TestGetCheckpoints_EmptyWorkflow(t *testing.T) {
	svc, _ := setupTestService(nil)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	resp, err := svc.GetCheckpoints(ctx, workflowID, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("GetCheckpoints failed: %v", err)
	}
	if len(resp.Checkpoints) != 0 {
		t.Errorf("expected 0 checkpoints, got %d", len(resp.Checkpoints))
	}
	if resp.WorkflowID != workflowID {
		t.Errorf("expected workflow ID %s, got %s", workflowID, resp.WorkflowID)
	}
}

func TestGetCheckpoints_TenantIsolation(t *testing.T) {
	svc, _ := setupTestService(nil)
	ctx := context.Background()

	// Create workflow as tenant-1
	wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "tenant-test",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow failed: %v", err)
	}

	// Try to access as tenant-2 — should get not found
	_, err = svc.GetCheckpoints(ctx, wf.WorkflowID, "tenant-2", "org-1")
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestGetCheckpoints_NonExistentWorkflow(t *testing.T) {
	svc, _ := setupTestService(nil)
	ctx := context.Background()

	_, err := svc.GetCheckpoints(ctx, "wf_nonexistent", "tenant-1", "org-1")
	if err == nil {
		t.Fatal("expected error for non-existent workflow")
	}
}

// --- GetLastResumableCheckpoint tests ---

func TestGetLastResumableCheckpoint_SkipsBlocked(t *testing.T) {
	svc, repo := setupTestService(nil)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Create 3 checkpoints: allow, block, allow
	repo.CreateCheckpoint(ctx, &Checkpoint{
		WorkflowID: workflowID, StepID: "step-1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "allow",
		IsResumable: true, OrgID: "org-1", TenantID: "tenant-1",
	})
	repo.CreateCheckpoint(ctx, &Checkpoint{
		WorkflowID: workflowID, StepID: "step-2", StepIndex: 2,
		CheckpointType: CheckpointStepGate, GateDecision: "block",
		IsResumable: false, OrgID: "org-1", TenantID: "tenant-1",
	})
	repo.CreateCheckpoint(ctx, &Checkpoint{
		WorkflowID: workflowID, StepID: "step-3", StepIndex: 3,
		CheckpointType: CheckpointStepGate, GateDecision: "allow",
		IsResumable: true, OrgID: "org-1", TenantID: "tenant-1",
	})

	cp, err := repo.GetLastResumableCheckpoint(ctx, workflowID)
	if err != nil {
		t.Fatalf("GetLastResumableCheckpoint failed: %v", err)
	}
	if cp == nil {
		t.Fatal("expected checkpoint, got nil")
	}
	if cp.StepID != "step-3" {
		t.Errorf("expected step-3 (highest resumable), got %s", cp.StepID)
	}
}

func TestGetLastResumableCheckpoint_NoResumable(t *testing.T) {
	svc, repo := setupTestService(nil)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Only blocked checkpoints
	repo.CreateCheckpoint(ctx, &Checkpoint{
		WorkflowID: workflowID, StepID: "step-1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "block",
		IsResumable: false,
	})

	cp, err := repo.GetLastResumableCheckpoint(ctx, workflowID)
	if err != nil {
		t.Fatalf("GetLastResumableCheckpoint failed: %v", err)
	}
	if cp != nil {
		t.Errorf("expected nil for no resumable checkpoints, got step %s", cp.StepID)
	}
}

// --- Resume tests ---

func TestResumeFromLastCheckpoint_Success(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionAllow, reason: "re-allowed"}
	svc, _ := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Create a step gate (creates checkpoint)
	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	// Resume from last checkpoint
	resp, err := svc.ResumeFromLastCheckpoint(ctx, workflowID, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("ResumeFromLastCheckpoint failed: %v", err)
	}
	if resp.ResumedFromCheckpoint != "step-1" {
		t.Errorf("expected resumed from step-1, got %s", resp.ResumedFromCheckpoint)
	}
	if resp.DecisionSource != "fresh" {
		t.Errorf("expected fresh, got %s", resp.DecisionSource)
	}
	if resp.ResumeCount != 1 {
		t.Errorf("expected resume_count=1, got %d", resp.ResumeCount)
	}
}

func TestResumeFromLastCheckpoint_NoCheckpoint(t *testing.T) {
	svc, _ := setupTestService(nil)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	_, err := svc.ResumeFromLastCheckpoint(ctx, workflowID, "tenant-1", "org-1")
	if err == nil {
		t.Fatal("expected error for no checkpoints")
	}
}

func TestResumeFromLastCheckpoint_CompletedWorkflow(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"}
	svc, _ := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	_, _ = svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	_ = svc.CompleteWorkflow(ctx, workflowID, "tenant-1", "org-1")

	_, err := svc.ResumeFromLastCheckpoint(ctx, workflowID, "tenant-1", "org-1")
	if err == nil {
		t.Fatal("expected error for completed workflow")
	}
}

func TestResumeFromCheckpoint_SpecificCheckpoint(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Create 2 step gates
	_, _ = svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	_, _ = svc.StepGate(ctx, workflowID, "step-2", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Get checkpoint for step-1
	checkpoints, _ := repo.ListCheckpoints(ctx, workflowID)
	if len(checkpoints) < 2 {
		t.Fatalf("expected 2 checkpoints, got %d", len(checkpoints))
	}

	step1CP := checkpoints[0]

	// Resume from step-1 (not the last)
	resp, err := svc.ResumeFromCheckpoint(ctx, workflowID, step1CP.ID, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("ResumeFromCheckpoint failed: %v", err)
	}
	if resp.ResumedFromCheckpoint != "step-1" {
		t.Errorf("expected step-1, got %s", resp.ResumedFromCheckpoint)
	}
}

func TestResumeFromCheckpoint_NonResumable(t *testing.T) {
	svc, repo := setupTestService(nil)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Create non-resumable checkpoint
	cp := &Checkpoint{
		WorkflowID: workflowID, StepID: "step-1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "block",
		IsResumable: false,
	}
	repo.CreateCheckpoint(ctx, cp)

	_, err := svc.ResumeFromCheckpoint(ctx, workflowID, cp.ID, "tenant-1", "org-1")
	if err == nil {
		t.Fatal("expected error for non-resumable checkpoint")
	}
}

func TestResumeFromCheckpoint_WrongWorkflow(t *testing.T) {
	svc, repo := setupTestService(nil)
	ctx := context.Background()

	wf1, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "wf1"}, "t1", "o1", "u1", "c1")
	wf2, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "wf2"}, "t1", "o1", "u1", "c1")

	cp := &Checkpoint{
		WorkflowID: wf1.WorkflowID, StepID: "step-1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "allow",
		IsResumable: true,
	}
	repo.CreateCheckpoint(ctx, cp)

	// Try to resume wf2 using wf1's checkpoint
	_, err := svc.ResumeFromCheckpoint(ctx, wf2.WorkflowID, cp.ID, "t1", "o1")
	if err == nil {
		t.Fatal("expected error for checkpoint from different workflow")
	}
}

func TestResumeFromCheckpoint_IncrementsCount(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	_, _ = svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Resume twice
	svc.ResumeFromLastCheckpoint(ctx, workflowID, "tenant-1", "org-1")
	resp, err := svc.ResumeFromLastCheckpoint(ctx, workflowID, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("second resume failed: %v", err)
	}
	if resp.ResumeCount != 2 {
		t.Errorf("expected resume_count=2, got %d", resp.ResumeCount)
	}

	// Verify in repo
	checkpoints, _ := repo.ListCheckpoints(ctx, workflowID)
	if checkpoints[0].ResumeCount != 2 {
		t.Errorf("repo resume_count should be 2, got %d", checkpoints[0].ResumeCount)
	}
}

// --- Mock checkpoint tests ---

func TestMockCheckpoint_CreateAndList(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	repo.Create(ctx, &Workflow{WorkflowID: "wf-1", WorkflowName: "test"})

	cp := &Checkpoint{
		WorkflowID: "wf-1", StepID: "s1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "allow",
		IsResumable: true,
	}
	err := repo.CreateCheckpoint(ctx, cp)
	if err != nil {
		t.Fatalf("CreateCheckpoint failed: %v", err)
	}
	if cp.ID == 0 {
		t.Error("expected non-zero ID")
	}

	list, err := repo.ListCheckpoints(ctx, "wf-1")
	if err != nil {
		t.Fatalf("ListCheckpoints failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}
}

func TestMockCheckpoint_Upsert(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	repo.Create(ctx, &Workflow{WorkflowID: "wf-1", WorkflowName: "test"})

	repo.CreateCheckpoint(ctx, &Checkpoint{
		WorkflowID: "wf-1", StepID: "s1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "allow",
		IsResumable: true,
	})
	repo.CreateCheckpoint(ctx, &Checkpoint{
		WorkflowID: "wf-1", StepID: "s1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "block",
		IsResumable: false,
	})

	list, _ := repo.ListCheckpoints(ctx, "wf-1")
	if len(list) != 1 {
		t.Fatalf("expected 1 after upsert, got %d", len(list))
	}
	if list[0].GateDecision != "block" {
		t.Errorf("expected updated decision 'block', got %s", list[0].GateDecision)
	}
}

func TestMockCheckpoint_GetByID(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	repo.Create(ctx, &Workflow{WorkflowID: "wf-1", WorkflowName: "test"})

	cp := &Checkpoint{
		WorkflowID: "wf-1", StepID: "s1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "allow",
		IsResumable: true,
	}
	repo.CreateCheckpoint(ctx, cp)

	found, err := repo.GetCheckpointByID(ctx, cp.ID)
	if err != nil {
		t.Fatalf("GetCheckpointByID failed: %v", err)
	}
	if found == nil {
		t.Fatal("expected checkpoint, got nil")
	}
	if found.StepID != "s1" {
		t.Errorf("expected s1, got %s", found.StepID)
	}

	// Non-existent ID
	notFound, err := repo.GetCheckpointByID(ctx, 9999)
	if err != nil {
		t.Fatalf("GetCheckpointByID for non-existent failed: %v", err)
	}
	if notFound != nil {
		t.Error("expected nil for non-existent checkpoint")
	}
}

func TestMockCheckpoint_IncrementResumeCount(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	repo.Create(ctx, &Workflow{WorkflowID: "wf-1", WorkflowName: "test"})

	cp := &Checkpoint{
		WorkflowID: "wf-1", StepID: "s1", StepIndex: 1,
		CheckpointType: CheckpointStepGate, GateDecision: "allow",
		IsResumable: true,
	}
	repo.CreateCheckpoint(ctx, cp)

	repo.IncrementResumeCount(ctx, cp.ID)
	repo.IncrementResumeCount(ctx, cp.ID)

	found, _ := repo.GetCheckpointByID(ctx, cp.ID)
	if found.ResumeCount != 2 {
		t.Errorf("expected resume_count=2, got %d", found.ResumeCount)
	}
	if found.LastResumedAt == nil {
		t.Error("expected last_resumed_at to be set")
	}
}

// --- Checkpoint serialization tests ---

func TestCheckpointType_Constants(t *testing.T) {
	if CheckpointStepGate != "step_gate" {
		t.Errorf("expected step_gate, got %s", CheckpointStepGate)
	}
	if CheckpointApprovalBoundary != "approval_boundary" {
		t.Errorf("expected approval_boundary, got %s", CheckpointApprovalBoundary)
	}
}

func TestCheckpoint_JSONSerialization(t *testing.T) {
	cp := Checkpoint{
		ID:             1,
		WorkflowID:     "wf-1",
		StepID:         "step-1",
		StepIndex:      1,
		CheckpointType: CheckpointStepGate,
		GateDecision:   "allow",
		IsResumable:    true,
		ResumeCount:    0,
	}

	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded Checkpoint
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.CheckpointType != CheckpointStepGate {
		t.Errorf("expected step_gate, got %s", decoded.CheckpointType)
	}
}

func TestResumeFromCheckpointResponse_JSON(t *testing.T) {
	resp := ResumeFromCheckpointResponse{
		WorkflowID:            "wf-1",
		ResumedFromCheckpoint: "step-2",
		ResumedFromIndex:      2,
		NewDecision:           "allow",
		DecisionSource:        "fresh",
		ResumeCount:           1,
		Message:               "Resumed",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	if raw["decision_source"] != "fresh" {
		t.Errorf("expected fresh, got %v", raw["decision_source"])
	}
	if raw["resume_count"].(float64) != 1 {
		t.Errorf("expected resume_count=1, got %v", raw["resume_count"])
	}
}

// --- Resume context preservation tests ---

// contextCapturingEvaluator records the StepGateContext it receives for verification.
type contextCapturingEvaluator struct {
	lastCtx  *StepGateContext
	decision GateDecision
}

func (e *contextCapturingEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	e.lastCtx = step
	return &StepGateEvaluation{
		Decision: e.decision,
		Reason:   "context-capture",
	}
}

func TestResumeFromCheckpoint_PreservesFullContext(t *testing.T) {
	evaluator := &contextCapturingEvaluator{decision: GateDecisionAllow}
	svc, _ := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Create a step gate with full context: model, provider, tool_context, step_name
	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepName: "Generate Report",
		StepType: StepTypeLLMCall,
		StepInput: map[string]interface{}{
			"prompt": "Generate Q4 revenue report",
		},
		Model:    "gpt-4",
		Provider: "openai",
		ToolContext: &ToolContext{
			ToolName: "report_generator",
			ToolType: "function",
			ToolInput: map[string]interface{}{
				"format": "pdf",
			},
		},
	}, "tenant-1", "org-1", "user-42", "client-web")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	// Clear the captured context
	evaluator.lastCtx = nil

	// Resume from last checkpoint
	_, err = svc.ResumeFromLastCheckpoint(ctx, workflowID, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("ResumeFromLastCheckpoint failed: %v", err)
	}

	// Verify the evaluator received the full original context
	if evaluator.lastCtx == nil {
		t.Fatal("evaluator was not called during resume")
	}
	captured := evaluator.lastCtx

	if captured.StepName != "Generate Report" {
		t.Errorf("step_name not preserved: got %q", captured.StepName)
	}
	if captured.StepType != StepTypeLLMCall {
		t.Errorf("step_type not preserved: got %q", captured.StepType)
	}
	if captured.Model != "gpt-4" {
		t.Errorf("model not preserved: got %q", captured.Model)
	}
	if captured.Provider != "openai" {
		t.Errorf("provider not preserved: got %q", captured.Provider)
	}
	if captured.UserID != "user-42" {
		t.Errorf("user_id not preserved: got %q", captured.UserID)
	}
	if captured.ClientID != "client-web" {
		t.Errorf("client_id not preserved: got %q", captured.ClientID)
	}
	if captured.ToolContext == nil {
		t.Fatal("tool_context not preserved: got nil")
	}
	if captured.ToolContext.ToolName != "report_generator" {
		t.Errorf("tool_name not preserved: got %q", captured.ToolContext.ToolName)
	}
	if captured.ToolContext.ToolType != "function" {
		t.Errorf("tool_type not preserved: got %q", captured.ToolContext.ToolType)
	}
	if captured.StepInput["prompt"] != "Generate Q4 revenue report" {
		t.Errorf("step_input not preserved: got %v", captured.StepInput)
	}
}

func TestStepGate_CheckpointStoresFullContext(t *testing.T) {
	evaluator := &fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepName: "Analyze Sentiment",
		StepType: StepTypeLLMCall,
		Model:    "claude-3",
		Provider: "anthropic",
		ToolContext: &ToolContext{
			ToolName: "sentiment_api",
			ToolType: "api",
		},
	}, "tenant-1", "org-1", "user-99", "client-mobile")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	checkpoints, _ := repo.ListCheckpoints(ctx, workflowID)
	if len(checkpoints) != 1 {
		t.Fatalf("expected 1 checkpoint, got %d", len(checkpoints))
	}

	cp := checkpoints[0]
	if cp.StepName != "Analyze Sentiment" {
		t.Errorf("checkpoint step_name: got %q", cp.StepName)
	}
	if cp.Model != "claude-3" {
		t.Errorf("checkpoint model: got %q", cp.Model)
	}
	if cp.Provider != "anthropic" {
		t.Errorf("checkpoint provider: got %q", cp.Provider)
	}
	if cp.UserID != "user-99" {
		t.Errorf("checkpoint user_id: got %q", cp.UserID)
	}
	if cp.ClientID != "client-mobile" {
		t.Errorf("checkpoint client_id: got %q", cp.ClientID)
	}
	if cp.ToolContext == nil {
		t.Fatal("checkpoint tool_context: got nil")
	}
	var tc ToolContext
	json.Unmarshal(cp.ToolContext, &tc)
	if tc.ToolName != "sentiment_api" {
		t.Errorf("checkpoint tool_name: got %q", tc.ToolName)
	}
}
