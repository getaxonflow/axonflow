// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Postgres-backed integration tests for Issue #1673 Phase 1 + Phase 2.
// Exercises the real DB path for:
//   - AddStep UPSERT semantics (counters, last_decision snapshot, idempotency_key COALESCE)
//   - BumpGateCountCached (cached-hit counter bump)
//   - MarkStepCompleted (completion_count increment)
//   - Full gate → complete → re-gate lifecycle with retry_context transitions
//
// Uses getTestDB / workflowControlSchema from repository_integration_test.go.

package workflow_control

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func seedWorkflow(t *testing.T, repo *PostgresRepository, tenantID string) string {
	t.Helper()
	id := fmt.Sprintf("wf_%d", time.Now().UnixNano())
	wf := &Workflow{
		WorkflowID:   id,
		WorkflowName: "integration-retry-context",
		Source:       WorkflowSourceExternal,
		TenantID:     tenantID,
	}
	if err := repo.Create(context.Background(), wf); err != nil {
		t.Fatalf("seed workflow: %v", err)
	}
	return id
}

// TestIntegration_AddStep_FirstCallSetsCountersAndFirstAttemptAt verifies
// the INSERT path: gate_count=1, completion_count=0, last_decision=decision,
// first_attempt_at=now, idempotency_key persisted.
func TestIntegration_AddStep_FirstCallSetsCountersAndFirstAttemptAt(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()
	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("tc-first-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)
	wf := seedWorkflow(t, repo, tenantID)

	key := "payment:wire:inv-1"
	step := &WorkflowStep{
		WorkflowID:     wf,
		StepID:         "s1",
		StepIndex:      1,
		StepType:       StepTypeToolCall,
		Decision:       GateDecisionAllow,
		IdempotencyKey: &key,
	}
	if err := repo.AddStep(context.Background(), step); err != nil {
		t.Fatalf("AddStep: %v", err)
	}

	if step.GateCount != 1 {
		t.Errorf("GateCount: want 1, got %d", step.GateCount)
	}
	if step.CompletionCount != 0 {
		t.Errorf("CompletionCount: want 0, got %d", step.CompletionCount)
	}
	if step.LastDecision != GateDecisionAllow {
		t.Errorf("LastDecision: want allow (first-call invariant), got %s", step.LastDecision)
	}
	if step.FirstAttemptAt == nil {
		t.Error("FirstAttemptAt: want non-nil after insert")
	}
	if step.IdempotencyKey == nil || *step.IdempotencyKey != key {
		t.Errorf("IdempotencyKey: want %q, got %v", key, step.IdempotencyKey)
	}
}

// TestIntegration_AddStep_ReGateBumpsCountAndSnapshotsLastDecision verifies
// the UPSERT branch on re-gate: counter bumps, OLD decision becomes
// last_decision, idempotency_key preserved even when caller supplies a
// different value (immutability via COALESCE).
func TestIntegration_AddStep_ReGateBumpsCountAndSnapshotsLastDecision(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()
	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("tc-regate-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)
	wf := seedWorkflow(t, repo, tenantID)

	ctx := context.Background()
	originalKey := "K-original"
	step := &WorkflowStep{
		WorkflowID:     wf,
		StepID:         "s1",
		StepIndex:      1,
		StepType:       StepTypeToolCall,
		Decision:       GateDecisionAllow,
		IdempotencyKey: &originalKey,
	}
	if err := repo.AddStep(ctx, step); err != nil {
		t.Fatalf("first AddStep: %v", err)
	}
	firstAttempt := *step.FirstAttemptAt

	// Simulate delay so first_attempt_at stays earlier than gate_checked_at
	time.Sleep(10 * time.Millisecond)

	// Re-gate with a NEW decision and DIFFERENT idempotency_key.
	// Repo should preserve first_attempt_at and keep the original key
	// (immutability enforced via COALESCE in the UPSERT).
	differentKey := "K-different"
	step2 := &WorkflowStep{
		WorkflowID:     wf,
		StepID:         "s1",
		StepIndex:      1,
		StepType:       StepTypeToolCall,
		Decision:       GateDecisionBlock, // changed
		IdempotencyKey: &differentKey,     // would-be new key
	}
	if err := repo.AddStep(ctx, step2); err != nil {
		t.Fatalf("re-AddStep: %v", err)
	}

	if step2.GateCount != 2 {
		t.Errorf("GateCount: want 2, got %d", step2.GateCount)
	}
	if step2.CompletionCount != 0 {
		t.Errorf("CompletionCount: want preserved 0, got %d", step2.CompletionCount)
	}
	// LastDecision should be the OLD (first) decision, not the new block.
	if step2.LastDecision != GateDecisionAllow {
		t.Errorf("LastDecision: want allow (snapshot of prior), got %s", step2.LastDecision)
	}
	if step2.FirstAttemptAt == nil || !step2.FirstAttemptAt.Equal(firstAttempt) {
		t.Errorf("FirstAttemptAt: want preserved %v, got %v", firstAttempt, step2.FirstAttemptAt)
	}
	if step2.IdempotencyKey == nil || *step2.IdempotencyKey != originalKey {
		t.Errorf("IdempotencyKey: want preserved %q (immutable), got %v", originalKey, step2.IdempotencyKey)
	}
}

// TestIntegration_BumpGateCountCached_OnlyTouchesCounterAndLastDecision
// verifies the UPDATE-only path used by the cached StepGate branch.
func TestIntegration_BumpGateCountCached_OnlyTouchesCounterAndLastDecision(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()
	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("tc-bump-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)
	wf := seedWorkflow(t, repo, tenantID)

	ctx := context.Background()
	step := &WorkflowStep{
		WorkflowID: wf,
		StepID:     "s1",
		StepIndex:  1,
		StepType:   StepTypeToolCall,
		Decision:   GateDecisionAllow,
	}
	if err := repo.AddStep(ctx, step); err != nil {
		t.Fatalf("AddStep: %v", err)
	}
	originalDecision := step.Decision
	originalFirstAttempt := *step.FirstAttemptAt

	time.Sleep(10 * time.Millisecond)

	bumped, err := repo.BumpGateCountCached(ctx, wf, "s1")
	if err != nil {
		t.Fatalf("BumpGateCountCached: %v", err)
	}
	if bumped.GateCount != 2 {
		t.Errorf("GateCount: want 2, got %d", bumped.GateCount)
	}
	if bumped.Decision != originalDecision {
		t.Errorf("Decision: want preserved %s, got %s", originalDecision, bumped.Decision)
	}
	if bumped.LastDecision != originalDecision {
		t.Errorf("LastDecision: want snapshotted %s, got %s", originalDecision, bumped.LastDecision)
	}
	if bumped.FirstAttemptAt == nil || !bumped.FirstAttemptAt.Equal(originalFirstAttempt) {
		t.Errorf("FirstAttemptAt: want preserved, got %v", bumped.FirstAttemptAt)
	}
}

// TestIntegration_MarkStepCompleted_IncrementsCompletionCount verifies the
// complete path bumps completion_count and that a subsequent GetStepDecision
// reflects the new value.
func TestIntegration_MarkStepCompleted_IncrementsCompletionCount(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()
	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("tc-complete-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)
	wf := seedWorkflow(t, repo, tenantID)

	ctx := context.Background()
	step := &WorkflowStep{
		WorkflowID: wf,
		StepID:     "s1",
		StepIndex:  1,
		StepType:   StepTypeToolCall,
		Decision:   GateDecisionAllow,
	}
	if err := repo.AddStep(ctx, step); err != nil {
		t.Fatalf("AddStep: %v", err)
	}

	if err := repo.MarkStepCompleted(ctx, wf, "s1", &StepCompleteRequest{}); err != nil {
		t.Fatalf("MarkStepCompleted: %v", err)
	}

	after, err := repo.GetStepDecision(ctx, wf, "s1")
	if err != nil {
		t.Fatalf("GetStepDecision: %v", err)
	}
	if after == nil {
		t.Fatal("expected step to exist after complete")
	}
	if after.CompletionCount != 1 {
		t.Errorf("CompletionCount: want 1, got %d", after.CompletionCount)
	}
	if after.StepCompletedAt == nil {
		t.Error("StepCompletedAt: want non-nil after complete")
	}
}

// TestIntegration_FullLifecycle_ThroughServiceLayer exercises the real
// service + repo end-to-end across every retry_context transition plus
// idempotency-key enforcement. This is the smoke test that verifies the
// platform as a unit, against a real Postgres.
func TestIntegration_FullLifecycle_ThroughServiceLayer(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()
	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("tc-full-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	svc := NewService(repo,
		&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"},
		&ServiceConfig{BaseURL: "https://portal.test"},
	)
	ctx := context.Background()
	wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "lifecycle",
	}, tenantID, "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	wfID := wf.WorkflowID

	key := "payment:wire:lifecycle-1"

	// 1) First gate — fresh path, key recorded
	resp1, err := svc.StepGate(ctx, wfID, "s1", &StepGateRequest{
		StepType:       StepTypeToolCall,
		IdempotencyKey: key,
	}, tenantID, "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 1: %v", err)
	}
	if resp1.RetryContext.GateCount != 1 ||
		resp1.RetryContext.PriorCompletionStatus != PriorCompletionStatusNone ||
		resp1.RetryContext.IdempotencyKey != key {
		t.Errorf("gate 1 retry_context unexpected: %+v", resp1.RetryContext)
	}

	// 2) Complete with matching key
	if err := svc.MarkStepCompleted(ctx, wfID, "s1", &StepCompleteRequest{
		IdempotencyKey: key,
		Output:         map[string]interface{}{"tx": "TXN-01"},
	}, tenantID, "org-1"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// 3) Re-gate (cached path) — expect status=completed, prior_output_available=true
	resp2, err := svc.StepGate(ctx, wfID, "s1", &StepGateRequest{
		StepType:       StepTypeToolCall,
		IdempotencyKey: key,
	}, tenantID, "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 2: %v", err)
	}
	if resp2.RetryContext.GateCount != 2 ||
		resp2.RetryContext.CompletionCount != 1 ||
		resp2.RetryContext.PriorCompletionStatus != PriorCompletionStatusCompleted ||
		!resp2.RetryContext.PriorOutputAvailable {
		t.Errorf("gate 2 retry_context unexpected: %+v", resp2.RetryContext)
	}
	if !resp2.Cached {
		t.Error("gate 2 should be Cached")
	}

	// 4) Second gate with WRONG key — 409 via service error
	_, err = svc.StepGate(ctx, wfID, "s1", &StepGateRequest{
		StepType:       StepTypeToolCall,
		IdempotencyKey: "K-different",
	}, tenantID, "org-1", "user-1", "client-1")
	if err == nil {
		t.Fatal("gate with mismatched key should fail")
	}
	if _, ok := err.(*IdempotencyKeyMismatchError); !ok {
		t.Errorf("want *IdempotencyKeyMismatchError, got %T: %v", err, err)
	}

	// 5) include_prior_output=true returns payload
	resp3, err := svc.StepGate(ctx, wfID, "s1", &StepGateRequest{
		StepType:           StepTypeToolCall,
		IdempotencyKey:     key,
		IncludePriorOutput: true,
	}, tenantID, "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 3: %v", err)
	}
	if resp3.RetryContext.PriorOutput == nil ||
		resp3.RetryContext.PriorOutput["tx"] != "TXN-01" {
		t.Errorf("gate 3 prior_output: want populated with tx=TXN-01, got %v",
			resp3.RetryContext.PriorOutput)
	}
}
