// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// countingEvaluator wraps a PolicyEvaluator and counts how many times EvaluateStepGate is called.
type countingEvaluator struct {
	inner PolicyEvaluator
	calls atomic.Int64
}

func newCountingEvaluator(inner PolicyEvaluator) *countingEvaluator {
	return &countingEvaluator{inner: inner}
}

func (e *countingEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	e.calls.Add(1)
	return e.inner.EvaluateStepGate(ctx, step)
}

// fixedEvaluator always returns the same decision.
type fixedEvaluator struct {
	decision GateDecision
	reason   string
}

func (e *fixedEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:          e.decision,
		Reason:            e.reason,
		PolicyIDs:         []string{"test-policy"},
		PoliciesEvaluated: []PolicyMatch{{PolicyID: "test-policy", PolicyName: "Test Policy", Action: string(e.decision)}},
		PoliciesMatched:   []PolicyMatch{{PolicyID: "test-policy", PolicyName: "Test Policy", Action: string(e.decision)}},
	}
}

func setupTestService(evaluator PolicyEvaluator) (*Service, *MockRepository) {
	repo := NewMockRepository()
	svc := NewService(repo, evaluator, &ServiceConfig{BaseURL: "https://portal.test"})
	return svc, repo
}

func createTestWorkflow(t *testing.T, svc *Service) string {
	t.Helper()
	ctx := context.Background()
	wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-retry-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("failed to create workflow: %v", err)
	}
	return wf.WorkflowID
}

// --- Idempotent retry tests ---

func TestStepGate_IdempotentDefault_ReturnsCachedDecision(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First call — fresh evaluation
	resp1, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}
	if resp1.Decision != GateDecisionAllow {
		t.Errorf("first call: expected allow, got %s", resp1.Decision)
	}
	if resp1.Cached {
		t.Error("first call should not be cached")
	}
	if resp1.DecisionSource != "fresh" {
		t.Errorf("first call: expected decision_source=fresh, got %s", resp1.DecisionSource)
	}

	// Second call — same (workflow_id, step_id), default retry_policy (idempotent)
	resp2, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("second StepGate failed: %v", err)
	}
	if resp2.Decision != GateDecisionAllow {
		t.Errorf("second call: expected allow, got %s", resp2.Decision)
	}
	if !resp2.Cached {
		t.Error("second call should be cached")
	}
	if resp2.DecisionSource != "cached" {
		t.Errorf("second call: expected decision_source=cached, got %s", resp2.DecisionSource)
	}

	// Policy evaluator should have been called exactly once
	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("expected evaluator to be called once, was called %d times", calls)
	}
}

func TestStepGate_ExplicitIdempotent_ReturnsCachedDecision(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionBlock, reason: "blocked"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First call
	resp1, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType:    StepTypeToolCall,
		RetryPolicy: RetryPolicyIdempotent,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}
	if resp1.Cached {
		t.Error("first call should not be cached")
	}

	// Second call with explicit idempotent
	resp2, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType:    StepTypeToolCall,
		RetryPolicy: RetryPolicyIdempotent,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("second StepGate failed: %v", err)
	}
	if !resp2.Cached {
		t.Error("second call should be cached")
	}
	if resp2.Decision != GateDecisionBlock {
		t.Errorf("expected block, got %s", resp2.Decision)
	}

	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("expected evaluator to be called once, was called %d times", calls)
	}
}

func TestStepGate_Reevaluate_ForcesFreshEvaluation(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First call
	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}

	// Second call with reevaluate
	resp2, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType:    StepTypeToolCall,
		RetryPolicy: RetryPolicyReevaluate,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("second StepGate failed: %v", err)
	}
	if resp2.Cached {
		t.Error("reevaluate should not be cached")
	}
	if resp2.DecisionSource != "fresh" {
		t.Errorf("expected decision_source=fresh, got %s", resp2.DecisionSource)
	}

	// Evaluator called twice
	if calls := counter.calls.Load(); calls != 2 {
		t.Errorf("expected evaluator to be called twice, was called %d times", calls)
	}
}

func TestStepGate_GateOverride_BypassesCache(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	override := GateDecisionRequireApproval

	// First call with GateOverride
	resp1, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType:     StepTypeToolCall,
		GateOverride: &override,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}
	if resp1.Decision != GateDecisionRequireApproval {
		t.Errorf("expected require_approval from override, got %s", resp1.Decision)
	}
	if resp1.Cached {
		t.Error("override should not be cached")
	}

	// Approve the step so we can call gate again
	err = svc.ApproveStep(ctx, workflowID, "step-1", "tenant-1", "org-1", "reviewer", "approved for test")
	if err != nil {
		t.Fatalf("ApproveStep failed: %v", err)
	}

	// Second call with GateOverride should NOT use cache even though step exists
	resp2, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType:     StepTypeToolCall,
		GateOverride: &override,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("second StepGate failed: %v", err)
	}
	if resp2.Decision != GateDecisionRequireApproval {
		t.Errorf("expected require_approval from override, got %s", resp2.Decision)
	}

	// Policy evaluator should NOT have been called (GateOverride bypasses evaluator)
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("expected evaluator to NOT be called with GateOverride, was called %d times", calls)
	}
}

// --- Cached approval state resolution tests ---

func TestStepGate_CachedRequireApproval_ApprovedReturnsAllow(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionRequireApproval, reason: "needs approval"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First call → require_approval
	resp1, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}
	if resp1.Decision != GateDecisionRequireApproval {
		t.Fatalf("expected require_approval, got %s", resp1.Decision)
	}

	// Approve the step
	err = svc.ApproveStep(ctx, workflowID, "step-1", "tenant-1", "org-1", "reviewer", "looks good to me")
	if err != nil {
		t.Fatalf("ApproveStep failed: %v", err)
	}

	// Second call — cached, should resolve to allow
	resp2, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("second StepGate failed: %v", err)
	}
	if resp2.Decision != GateDecisionAllow {
		t.Errorf("expected allow after approval, got %s", resp2.Decision)
	}
	if !resp2.Cached {
		t.Error("should be cached")
	}
	if resp2.ApprovalURL != "" {
		t.Error("approved step should not have approval URL")
	}

	// Evaluator still called only once
	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("expected evaluator to be called once, was called %d times", calls)
	}
}

func TestStepGate_ReevaluateAfterApproval_FreshEvaluation(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionRequireApproval, reason: "needs approval"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First call → require_approval
	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}

	// Approve
	err = svc.ApproveStep(ctx, workflowID, "step-1", "tenant-1", "org-1", "reviewer", "approved for test")
	if err != nil {
		t.Fatalf("ApproveStep failed: %v", err)
	}

	// Idempotent retry → should return cached allow (approved)
	resp2, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
	if resp2.Decision != GateDecisionAllow {
		t.Errorf("idempotent after approval: expected allow, got %s", resp2.Decision)
	}
	if !resp2.Cached {
		t.Error("idempotent after approval should be cached")
	}

	// Reevaluate → should run evaluator again, NOT return cached allow
	resp3, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType:    StepTypeToolCall,
		RetryPolicy: RetryPolicyReevaluate,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("reevaluate after approval failed: %v", err)
	}
	if resp3.Cached {
		t.Error("reevaluate should NOT be cached")
	}
	if resp3.DecisionSource != "fresh" {
		t.Errorf("expected fresh, got %s", resp3.DecisionSource)
	}

	// Evaluator should have been called twice (first call + reevaluate)
	if calls := counter.calls.Load(); calls != 2 {
		t.Errorf("expected evaluator called twice, was called %d times", calls)
	}
}

func TestStepGate_CachedRequireApproval_PendingReturnsCachedDecision(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionRequireApproval, reason: "needs approval"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First call → require_approval with pending status
	resp1, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}
	if resp1.Decision != GateDecisionRequireApproval {
		t.Fatalf("expected require_approval, got %s", resp1.Decision)
	}

	// Retry the SAME step — should return cached require_approval, not an error.
	// The idempotent cache lookup runs before the pending-approval guard, so
	// retrying the same (workflow_id, step_id) returns the cached decision.
	resp2, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("retry of pending step should not error, got: %v", err)
	}
	if resp2.Decision != GateDecisionRequireApproval {
		t.Errorf("expected require_approval, got %s", resp2.Decision)
	}
	if !resp2.Cached {
		t.Error("retry should be cached")
	}
	if resp2.ApprovalURL == "" {
		t.Error("pending step should have approval URL")
	}

	// Evaluator should have been called only once (the first time)
	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("expected evaluator called once, was called %d times", calls)
	}
}

func TestStepGate_PendingApproval_BlocksNewStep(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionRequireApproval, reason: "needs approval"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First step → require_approval
	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}

	// Try a DIFFERENT step while step-1 is pending — should be blocked
	_, err = svc.StepGate(ctx, workflowID, "step-2", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err == nil {
		t.Fatal("expected error: new step should be blocked while previous step has pending approval")
	}
	if !strings.Contains(err.Error(), "pending approval") {
		t.Errorf("expected pending approval error, got: %v", err)
	}
}

func TestStepGate_CachedRequireApproval_RejectedReturnsBlock(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionRequireApproval, reason: "needs approval"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// First call → require_approval
	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first StepGate failed: %v", err)
	}

	// Reject the step (this aborts the workflow)
	err = svc.RejectStep(ctx, workflowID, "step-1", "tenant-1", "org-1", "reviewer", "not allowed")
	if err != nil {
		t.Fatalf("RejectStep failed: %v", err)
	}

	// Workflow is now aborted, so StepGate returns terminal state error
	_, err = svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err == nil {
		t.Fatal("expected error for terminal workflow")
	}
}

// --- Different steps are independent ---

func TestStepGate_DifferentSteps_IndependentDecisions(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Step 1
	resp1, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("step-1 failed: %v", err)
	}
	if resp1.Cached {
		t.Error("step-1 should not be cached")
	}

	// Step 2 — different step, should evaluate fresh
	resp2, err := svc.StepGate(ctx, workflowID, "step-2", &StepGateRequest{
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("step-2 failed: %v", err)
	}
	if resp2.Cached {
		t.Error("step-2 should not be cached")
	}

	// Evaluator called twice (once per unique step)
	if calls := counter.calls.Load(); calls != 2 {
		t.Errorf("expected 2 evaluator calls, got %d", calls)
	}

	// Retry step 1 — should be cached
	resp3, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("step-1 retry failed: %v", err)
	}
	if !resp3.Cached {
		t.Error("step-1 retry should be cached")
	}

	// Still only 2 evaluator calls
	if calls := counter.calls.Load(); calls != 2 {
		t.Errorf("expected 2 evaluator calls after retry, got %d", calls)
	}
}

// --- Concurrent access ---

func TestStepGate_ConcurrentCalls_ConsistentResults(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	const goroutines = 10
	var wg sync.WaitGroup
	results := make([]*StepGateResponse, goroutines)
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errors[idx] = svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
				StepType: StepTypeToolCall,
			}, "tenant-1", "org-1", "user-1", "client-1")
		}(i)
	}

	wg.Wait()

	// All calls should succeed
	for i, err := range errors {
		if err != nil {
			t.Errorf("goroutine %d failed: %v", i, err)
		}
	}

	// All should return the same decision — the persisted winner.
	// With the read-back-after-upsert pattern (#1414 P3), even if multiple
	// goroutines evaluated concurrently, they all return the same decision
	// because the response is built from what persisted in the DB.
	var firstDecision GateDecision
	for i, resp := range results {
		if resp == nil {
			continue
		}
		if firstDecision == "" {
			firstDecision = resp.Decision
		}
		if resp.Decision != firstDecision {
			t.Errorf("goroutine %d: inconsistent decision %s (expected %s)", i, resp.Decision, firstDecision)
		}
	}
}

// --- buildCachedResponse tests ---

func TestBuildCachedResponse_Allow(t *testing.T) {
	step := &WorkflowStep{
		StepID:         "step-1",
		Decision:       GateDecisionAllow,
		DecisionReason: "allowed by policy",
		PoliciesEvaluated: mustMarshal([]PolicyMatch{
			{PolicyID: "p1", PolicyName: "Policy 1", Action: "allow"},
		}),
		PoliciesMatched: mustMarshal([]PolicyMatch{
			{PolicyID: "p1", PolicyName: "Policy 1", Action: "allow"},
		}),
	}

	resp := buildCachedResponse(step, "wf-1", "https://portal.test")

	if resp.Decision != GateDecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
	if !resp.Cached {
		t.Error("expected cached=true")
	}
	if resp.DecisionSource != "cached" {
		t.Errorf("expected decision_source=cached, got %s", resp.DecisionSource)
	}
	if resp.ApprovalURL != "" {
		t.Error("allow decision should not have approval URL")
	}
	if len(resp.PoliciesMatched) != 1 {
		t.Errorf("expected 1 matched policy, got %d", len(resp.PoliciesMatched))
	}
	if len(resp.PolicyIDs) != 1 || resp.PolicyIDs[0] != "p1" {
		t.Errorf("expected policy ID p1, got %v", resp.PolicyIDs)
	}
}

func TestBuildCachedResponse_RequireApproval_Approved(t *testing.T) {
	approved := ApprovalStatusApproved
	step := &WorkflowStep{
		StepID:            "step-1",
		Decision:          GateDecisionRequireApproval,
		DecisionReason:    "needs human approval",
		ApprovalStatus:    &approved,
		PoliciesEvaluated: mustMarshal([]PolicyMatch{}),
		PoliciesMatched:   mustMarshal([]PolicyMatch{}),
	}

	resp := buildCachedResponse(step, "wf-1", "https://portal.test")

	if resp.Decision != GateDecisionAllow {
		t.Errorf("approved step should resolve to allow, got %s", resp.Decision)
	}
	if resp.ApprovalURL != "" {
		t.Error("approved step should not have approval URL")
	}
}

func TestBuildCachedResponse_RequireApproval_Rejected(t *testing.T) {
	rejected := ApprovalStatusRejected
	step := &WorkflowStep{
		StepID:            "step-1",
		Decision:          GateDecisionRequireApproval,
		DecisionReason:    "needs human approval",
		ApprovalStatus:    &rejected,
		PoliciesEvaluated: mustMarshal([]PolicyMatch{}),
		PoliciesMatched:   mustMarshal([]PolicyMatch{}),
	}

	resp := buildCachedResponse(step, "wf-1", "https://portal.test")

	if resp.Decision != GateDecisionBlock {
		t.Errorf("rejected step should resolve to block, got %s", resp.Decision)
	}
}

func TestBuildCachedResponse_RequireApproval_Pending(t *testing.T) {
	pending := ApprovalStatusPending
	step := &WorkflowStep{
		StepID:            "step-1",
		Decision:          GateDecisionRequireApproval,
		DecisionReason:    "needs human approval",
		ApprovalStatus:    &pending,
		PoliciesEvaluated: mustMarshal([]PolicyMatch{}),
		PoliciesMatched:   mustMarshal([]PolicyMatch{}),
	}

	resp := buildCachedResponse(step, "wf-1", "https://portal.test")

	if resp.Decision != GateDecisionRequireApproval {
		t.Errorf("pending step should stay require_approval, got %s", resp.Decision)
	}
	if resp.ApprovalURL == "" {
		t.Error("pending step should have approval URL")
	}
}

func TestBuildCachedResponse_Block(t *testing.T) {
	step := &WorkflowStep{
		StepID:            "step-1",
		Decision:          GateDecisionBlock,
		DecisionReason:    "blocked by policy",
		PoliciesEvaluated: mustMarshal([]PolicyMatch{}),
		PoliciesMatched:   mustMarshal([]PolicyMatch{}),
	}

	resp := buildCachedResponse(step, "wf-1", "https://portal.test")

	if resp.Decision != GateDecisionBlock {
		t.Errorf("expected block, got %s", resp.Decision)
	}
}

// --- ValidRetryPolicy tests ---

func TestValidRetryPolicy(t *testing.T) {
	tests := []struct {
		policy RetryPolicy
		valid  bool
	}{
		{"", true},
		{RetryPolicyIdempotent, true},
		{RetryPolicyReevaluate, true},
		{"invalid", false},
		{"IDEMPOTENT", false},
		{"retry", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.policy), func(t *testing.T) {
			if got := ValidRetryPolicy(tt.policy); got != tt.valid {
				t.Errorf("ValidRetryPolicy(%q) = %v, want %v", tt.policy, got, tt.valid)
			}
		})
	}
}

// --- JSON serialization ---

func TestRetryPolicyJSONSerialization(t *testing.T) {
	req := StepGateRequest{
		StepType:    StepTypeToolCall,
		RetryPolicy: RetryPolicyReevaluate,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded StepGateRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.RetryPolicy != RetryPolicyReevaluate {
		t.Errorf("expected reevaluate, got %s", decoded.RetryPolicy)
	}
}

func TestRetryPolicyOmitEmpty(t *testing.T) {
	req := StepGateRequest{
		StepType: StepTypeToolCall,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// retry_policy should be omitted when empty
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}
	if _, ok := raw["retry_policy"]; ok {
		t.Error("retry_policy should be omitted when empty")
	}
}

func TestResponseCachedFieldsSerialized(t *testing.T) {
	resp := StepGateResponse{
		Decision:       GateDecisionAllow,
		StepID:         "step-1",
		Cached:         true,
		DecisionSource: "cached",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	if cached, ok := raw["cached"].(bool); !ok || !cached {
		t.Error("cached field should be true in JSON")
	}
	if ds, ok := raw["decision_source"].(string); !ok || ds != "cached" {
		t.Errorf("decision_source should be 'cached', got %v", raw["decision_source"])
	}
}

func TestResponseFreshFieldsSerialized(t *testing.T) {
	resp := StepGateResponse{
		Decision:       GateDecisionAllow,
		StepID:         "step-1",
		Cached:         false,
		DecisionSource: "fresh",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	// cached=false should still be serialized (not omitempty)
	if cached, ok := raw["cached"].(bool); !ok || cached {
		t.Error("cached field should be false in JSON")
	}
	if ds, ok := raw["decision_source"].(string); !ok || ds != "fresh" {
		t.Errorf("decision_source should be 'fresh', got %v", raw["decision_source"])
	}
}

// --- Helpers ---

func mustMarshal(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
