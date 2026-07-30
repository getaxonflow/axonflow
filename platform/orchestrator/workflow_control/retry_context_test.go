// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Tests for Issue #1673 Phase 1 (retry_context) + Phase 2 (idempotency_key).
//
// These exercise the service + mock-repository stack so we verify counter
// bookkeeping, prior_completion_status transitions, and idempotency-key
// validation at the same level the Postgres repo enforces them in production.
//
// The contract these tests target is
// technical-docs/WCP_RETRY_IDEMPOTENCY_WIRE_CONTRACT.md.

package workflow_control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// --- Phase 1: retry_context construction ---

// TestRetryContext_FirstCall_Invariants covers the first-call shape promised by
// contract §3. Every invariant is checked: counters == 1/0, status == none,
// first_attempt == last_attempt, last_decision == decision.
func TestRetryContext_FirstCall_Invariants(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	resp, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("first gate failed: %v", err)
	}

	rc := resp.RetryContext
	if rc.GateCount != 1 {
		t.Errorf("GateCount: want 1, got %d", rc.GateCount)
	}
	if rc.CompletionCount != 0 {
		t.Errorf("CompletionCount: want 0, got %d", rc.CompletionCount)
	}
	if rc.PriorCompletionStatus != PriorCompletionStatusNone {
		t.Errorf("PriorCompletionStatus: want none, got %s", rc.PriorCompletionStatus)
	}
	if rc.PriorOutputAvailable {
		t.Error("PriorOutputAvailable: want false, got true")
	}
	if rc.PriorOutput != nil {
		t.Error("PriorOutput: want nil on first call")
	}
	if rc.PriorCompletionAt != nil {
		t.Error("PriorCompletionAt: want nil on first call")
	}
	if rc.LastDecision != resp.Decision {
		t.Errorf("first-call invariant broken: LastDecision=%s, Decision=%s", rc.LastDecision, resp.Decision)
	}
	if !rc.FirstAttemptAt.Equal(rc.LastAttemptAt) {
		t.Errorf("first-call invariant broken: FirstAttemptAt=%v != LastAttemptAt=%v",
			rc.FirstAttemptAt, rc.LastAttemptAt)
	}
	if rc.IdempotencyKey != "" {
		t.Errorf("IdempotencyKey: want empty on no-key call, got %q", rc.IdempotencyKey)
	}
}

// TestRetryContext_SecondGate_WithCompletion covers the canonical "upstream
// retried after a clean completion" scenario (contract's Scenario A). Expected:
// counters bump, prior_completion_status = completed, prior_output_available = true.
func TestRetryContext_SecondGate_WithCompletion(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Gate 1 + Complete
	if _, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("gate 1: %v", err)
	}
	out := map[string]interface{}{"transfer_id": "TXN-1"}
	if err := svc.MarkStepCompleted(ctx, wf, "step-1", &StepCompleteRequest{Output: out},
		"tenant-1", "org-1"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Gate 2 (no include_prior_output)
	resp, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 2: %v", err)
	}

	rc := resp.RetryContext
	if rc.GateCount != 2 {
		t.Errorf("GateCount: want 2, got %d", rc.GateCount)
	}
	if rc.CompletionCount != 1 {
		t.Errorf("CompletionCount: want 1, got %d", rc.CompletionCount)
	}
	if rc.PriorCompletionStatus != PriorCompletionStatusCompleted {
		t.Errorf("PriorCompletionStatus: want completed, got %s", rc.PriorCompletionStatus)
	}
	if !rc.PriorOutputAvailable {
		t.Error("PriorOutputAvailable: want true after complete")
	}
	if rc.PriorOutput != nil {
		t.Errorf("PriorOutput should be nil without ?include_prior_output=true, got %v", rc.PriorOutput)
	}
	if rc.PriorCompletionAt == nil {
		t.Error("PriorCompletionAt: want non-nil after complete")
	}
}

// TestRetryContext_IncludePriorOutput_True verifies opt-in prior_output.
func TestRetryContext_IncludePriorOutput_True(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	if _, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("gate 1: %v", err)
	}
	out := map[string]interface{}{"transfer_id": "TXN-42", "amount": 500.0}
	if err := svc.MarkStepCompleted(ctx, wf, "step-1", &StepCompleteRequest{Output: out},
		"tenant-1", "org-1"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	resp, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{
		StepType:           StepTypeToolCall,
		IncludePriorOutput: true,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 2: %v", err)
	}
	if resp.RetryContext.PriorOutput == nil {
		t.Fatal("PriorOutput: want populated with include_prior_output=true")
	}
	if got := resp.RetryContext.PriorOutput["transfer_id"]; got != "TXN-42" {
		t.Errorf("PriorOutput[transfer_id]: want TXN-42, got %v", got)
	}
}

// TestRetryContext_SecondGate_NoCompletion covers the "uncertain territory"
// scenario — agent crashed between gate and complete, retries with no prior
// /complete. Expected: prior_completion_status = gated_not_completed.
func TestRetryContext_SecondGate_NoCompletion(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	// Gate 1, no complete
	if _, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("gate 1: %v", err)
	}

	resp, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 2: %v", err)
	}

	rc := resp.RetryContext
	if rc.GateCount != 2 {
		t.Errorf("GateCount: want 2, got %d", rc.GateCount)
	}
	if rc.CompletionCount != 0 {
		t.Errorf("CompletionCount: want 0, got %d", rc.CompletionCount)
	}
	if rc.PriorCompletionStatus != PriorCompletionStatusGatedNotCompleted {
		t.Errorf("PriorCompletionStatus: want gated_not_completed, got %s", rc.PriorCompletionStatus)
	}
	if rc.PriorOutputAvailable {
		t.Error("PriorOutputAvailable: want false with no prior complete")
	}
}

// TestRetryContext_LastDecision_SnapshotsPriorDecision verifies that
// last_decision on the response reflects the decision of the PRIOR gate call
// (not the current). Covers the reevaluate case where decision changes.
func TestRetryContext_LastDecision_SnapshotsPriorDecision(t *testing.T) {
	// First evaluator allows, then we swap to block for a reevaluate.
	eval := &switchableEvaluator{current: GateDecisionAllow}
	svc, _ := setupTestService(eval)
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	resp1, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 1: %v", err)
	}
	if resp1.RetryContext.LastDecision != GateDecisionAllow {
		t.Errorf("gate 1 first-call invariant broken: LastDecision=%s", resp1.RetryContext.LastDecision)
	}

	// Reevaluate with a different decision
	eval.current = GateDecisionBlock
	resp2, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{
		StepType:    StepTypeToolCall,
		RetryPolicy: RetryPolicyReevaluate,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 2 (reevaluate): %v", err)
	}
	if resp2.Decision != GateDecisionBlock {
		t.Errorf("gate 2 decision: want block (reevaluated), got %s", resp2.Decision)
	}
	if resp2.RetryContext.LastDecision != GateDecisionAllow {
		t.Errorf("gate 2 LastDecision: want allow (prior), got %s", resp2.RetryContext.LastDecision)
	}

	// Cached retry after the block: LastDecision becomes block (most recent
	// decision becomes the "prior" for the next call).
	resp3, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 3: %v", err)
	}
	if resp3.RetryContext.LastDecision != GateDecisionBlock {
		t.Errorf("gate 3 LastDecision: want block (prior cached call), got %s", resp3.RetryContext.LastDecision)
	}
}

// TestRetryContext_GateCount_BumpsOnCachedRetries verifies that even the cached
// path bumps gate_count — otherwise a busy retry loop would appear static.
func TestRetryContext_GateCount_BumpsOnCachedRetries(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		resp, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
			"tenant-1", "org-1", "user-1", "client-1")
		if err != nil {
			t.Fatalf("gate %d: %v", i, err)
		}
		if resp.RetryContext.GateCount != i {
			t.Errorf("gate %d: GateCount want %d, got %d", i, i, resp.RetryContext.GateCount)
		}
		if i > 1 && !resp.Cached {
			t.Errorf("gate %d: should be cached", i)
		}
	}
}

// TestRetryContext_CachedDeprecatedFieldsPreserved ensures the deprecated
// cached/decision_source fields still populate on every response, so existing
// SDK clients continue to work during the deprecation window.
func TestRetryContext_CachedDeprecatedFieldsPreserved(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	resp1, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 1: %v", err)
	}
	if resp1.Cached || resp1.DecisionSource != "fresh" {
		t.Errorf("gate 1: want cached=false decision_source=fresh, got cached=%v source=%s",
			resp1.Cached, resp1.DecisionSource)
	}

	resp2, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{StepType: StepTypeToolCall},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 2: %v", err)
	}
	if !resp2.Cached || resp2.DecisionSource != "cached" {
		t.Errorf("gate 2: want cached=true decision_source=cached, got cached=%v source=%s",
			resp2.Cached, resp2.DecisionSource)
	}
}

// TestRetryContext_EmptyIdempotencyKey_EmitsAsEmptyString is a shape lock
// for the case the caller did not supply an idempotency_key. Per contract
// §3 the field is always in the schema — emitted as empty string `""`,
// never omitted and never null. If the JSON tag on RetryContext.IdempotencyKey
// silently gains an `omitempty`, SDK deserializers that treat the field as
// required will break; this test catches that.
func TestRetryContext_EmptyIdempotencyKey_EmitsAsEmptyString(t *testing.T) {
	rc := RetryContext{
		GateCount:             1,
		CompletionCount:       0,
		PriorCompletionStatus: PriorCompletionStatusNone,
		FirstAttemptAt:        time.Unix(0, 0).UTC(),
		LastAttemptAt:         time.Unix(0, 0).UTC(),
		LastDecision:          GateDecisionAllow,
		IdempotencyKey:        "",
	}
	data, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	v, ok := decoded["idempotency_key"]
	if !ok {
		t.Fatalf("idempotency_key must be present even when empty; raw JSON: %s", string(data))
	}
	if v != "" {
		t.Errorf("idempotency_key: want empty string, got %v", v)
	}
}

// TestAPIError_EmptyKeys_EmitAsEmptyString mirrors the shape lock for the
// 409 envelope. Contract §5 says expected/received keys "will be the empty
// string" when one side is absent; both fields must emit as "" not be
// omitted, so SDK typed errors can always render them side-by-side.
func TestAPIError_EmptyKeys_EmitAsEmptyString(t *testing.T) {
	envelope := APIErrorResponse{
		Error: APIError{
			Code:    ErrorCodeIdempotencyKeyMismatch,
			Message: "idempotency_key does not match",
			Details: APIErrorDetails{
				WorkflowID:             "wf_1",
				StepID:                 "step-1",
				ExpectedIdempotencyKey: "", // gate had no key, complete did
				ReceivedIdempotencyKey: "K-received",
			},
		},
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	details := decoded["error"].(map[string]interface{})["details"].(map[string]interface{})
	if _, ok := details["expected_idempotency_key"]; !ok {
		t.Errorf("expected_idempotency_key must be present when empty; raw JSON: %s", string(data))
	}
	if details["expected_idempotency_key"] != "" {
		t.Errorf("expected_idempotency_key: want empty string, got %v", details["expected_idempotency_key"])
	}
	if details["received_idempotency_key"] != "K-received" {
		t.Errorf("received_idempotency_key round-trip: want K-received, got %v", details["received_idempotency_key"])
	}
}

// TestRetryContext_MarshalsToJSONShape is a shape lock — the JSON produced by
// Encode must match the wire contract in technical-docs/WCP_RETRY_IDEMPOTENCY_WIRE_CONTRACT.md §3.
// If this test breaks, an SDK's deserializer will also break.
func TestRetryContext_MarshalsToJSONShape(t *testing.T) {
	k := "payment:wire:invoice-77"
	now := time.Date(2026, 4, 21, 15, 30, 45, 0, time.UTC)
	done := now.Add(5 * time.Second)
	rc := RetryContext{
		GateCount:             2,
		CompletionCount:       1,
		PriorCompletionStatus: PriorCompletionStatusCompleted,
		PriorOutputAvailable:  true,
		PriorOutput:           nil, // opt-in, still in schema as null
		PriorCompletionAt:     &done,
		FirstAttemptAt:        now,
		LastAttemptAt:         now.Add(10 * time.Second),
		LastDecision:          GateDecisionAllow,
		IdempotencyKey:        k,
	}

	data, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Every field must be present (no omitempty on the contract surface —
	// idempotency_key is the exception because it's optional per §3).
	for _, field := range []string{
		"gate_count", "completion_count", "prior_completion_status",
		"prior_output_available", "prior_output", "prior_completion_at",
		"first_attempt_at", "last_attempt_at", "last_decision",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing required field %q in retry_context JSON", field)
		}
	}
	if decoded["prior_output"] != nil {
		t.Error("prior_output must marshal as null when nil, not omitted")
	}
	if decoded["gate_count"].(float64) != 2 {
		t.Errorf("gate_count round-trip: want 2, got %v", decoded["gate_count"])
	}
	if decoded["idempotency_key"] != k {
		t.Errorf("idempotency_key: want %q, got %v", k, decoded["idempotency_key"])
	}
}

// --- Phase 2: idempotency_key validation ---

// TestIdempotencyKey_GateRoundTrip verifies that the key provided on the first
// gate is echoed on subsequent gate retry_contexts and passes to /complete.
func TestIdempotencyKey_GateRoundTrip(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	key := "payment:wire:invoice-1"
	resp1, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{
		StepType:       StepTypeToolCall,
		IdempotencyKey: key,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 1: %v", err)
	}
	if resp1.RetryContext.IdempotencyKey != key {
		t.Errorf("gate 1 retry_context.idempotency_key: want %q, got %q", key, resp1.RetryContext.IdempotencyKey)
	}

	// Gate 2 with same key → OK and echoed
	resp2, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{
		StepType:       StepTypeToolCall,
		IdempotencyKey: key,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("gate 2 same key: %v", err)
	}
	if resp2.RetryContext.IdempotencyKey != key {
		t.Errorf("gate 2 retry_context.idempotency_key: want %q, got %q", key, resp2.RetryContext.IdempotencyKey)
	}

	// Complete with matching key → OK
	if err := svc.MarkStepCompleted(ctx, wf, "step-1", &StepCompleteRequest{
		IdempotencyKey: key,
	}, "tenant-1", "org-1"); err != nil {
		t.Errorf("complete with matching key should succeed: %v", err)
	}
}

// TestIdempotencyKey_StrictMismatch covers every row of contract §5's rules.
func TestIdempotencyKey_StrictMismatch(t *testing.T) {
	type scenario struct {
		name              string
		gateKey           string
		secondActionKey   string
		secondIsComplete  bool // true: /complete; false: /gate
		wantMismatchError bool
	}
	tests := []scenario{
		{"gate-K1,complete-K1", "K1", "K1", true, false},
		{"gate-K1,complete-K2", "K1", "K2", true, true},
		{"gate-K1,complete-no-key", "K1", "", true, true},
		{"gate-no-key,complete-K1", "", "K1", true, true},
		{"gate-no-key,complete-no-key", "", "", true, false},
		{"gate-K1,gate-K1", "K1", "K1", false, false},
		{"gate-K1,gate-K2", "K1", "K2", false, true},
		{"gate-K1,gate-no-key", "K1", "", false, true},
		{"gate-no-key,gate-K1", "", "K1", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
			wf := createTestWorkflow(t, svc)
			ctx := context.Background()

			if _, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{
				StepType:       StepTypeToolCall,
				IdempotencyKey: tc.gateKey,
			}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
				t.Fatalf("initial gate: %v", err)
			}

			var err error
			if tc.secondIsComplete {
				err = svc.MarkStepCompleted(ctx, wf, "step-1", &StepCompleteRequest{
					IdempotencyKey: tc.secondActionKey,
				}, "tenant-1", "org-1")
			} else {
				_, err = svc.StepGate(ctx, wf, "step-1", &StepGateRequest{
					StepType:       StepTypeToolCall,
					IdempotencyKey: tc.secondActionKey,
				}, "tenant-1", "org-1", "user-1", "client-1")
			}

			var mismatchErr *IdempotencyKeyMismatchError
			gotMismatch := errors.As(err, &mismatchErr)
			if gotMismatch != tc.wantMismatchError {
				t.Errorf("want mismatch=%v, got err=%v", tc.wantMismatchError, err)
			}
			if gotMismatch {
				if mismatchErr.ExpectedKey != tc.gateKey {
					t.Errorf("ExpectedKey: want %q, got %q", tc.gateKey, mismatchErr.ExpectedKey)
				}
				if mismatchErr.ReceivedKey != tc.secondActionKey {
					t.Errorf("ReceivedKey: want %q, got %q", tc.secondActionKey, mismatchErr.ReceivedKey)
				}
			}
		})
	}
}

// TestIdempotencyKey_AuditTrail verifies the key lands on both step_gate and
// step_completed audit entries (contract §4 last bullet).
func TestIdempotencyKey_AuditTrail(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	wf := createTestWorkflow(t, svc)
	ctx := context.Background()

	capture := &captureAuditLogger{}
	svc.SetAuditLogger(capture)

	key := "payment:wire:audit-1"
	if _, err := svc.StepGate(ctx, wf, "step-1", &StepGateRequest{
		StepType:       StepTypeToolCall,
		IdempotencyKey: key,
	}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("gate: %v", err)
	}
	if err := svc.MarkStepCompleted(ctx, wf, "step-1", &StepCompleteRequest{
		IdempotencyKey: key,
	}, "tenant-1", "org-1"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	var gateEntry, completeEntry *WorkflowAuditEntry
	for i, e := range capture.entries {
		switch e.Operation {
		case "step_gate":
			gateEntry = capture.entries[i]
		case "step_completed":
			completeEntry = capture.entries[i]
		}
	}
	if gateEntry == nil {
		t.Fatal("no step_gate audit entry captured")
	}
	if got := gateEntry.Metadata["idempotency_key"]; got != key {
		t.Errorf("step_gate audit metadata idempotency_key: want %q, got %v", key, got)
	}
	if completeEntry == nil {
		t.Fatal("no step_completed audit entry captured")
	}
	if got := completeEntry.Metadata["idempotency_key"]; got != key {
		t.Errorf("step_completed audit metadata idempotency_key: want %q, got %v", key, got)
	}
}

// --- Policy-semantics ---

// TestApplyRetryContextToGate_Semantics covers every branch of the helper
// that feeds the policy evaluator's retry-aware context. On the fresh path
// the policy engine sees values BEFORE the upcoming DB write — verify
// projected counter semantics.
func TestApplyRetryContextToGate_Semantics(t *testing.T) {
	t.Run("no existing step → first-call projections", func(t *testing.T) {
		var gate StepGateContext
		applyRetryContextToGate(&gate, nil, "")
		if gate.GateCount != 1 {
			t.Errorf("GateCount: want 1, got %d", gate.GateCount)
		}
		if gate.CompletionCount != 0 {
			t.Errorf("CompletionCount: want 0, got %d", gate.CompletionCount)
		}
		if gate.PriorCompletionStatus != PriorCompletionStatusNone {
			t.Errorf("PriorCompletionStatus: want none, got %s", gate.PriorCompletionStatus)
		}
		if gate.LastDecision != "" {
			t.Errorf("LastDecision on first call should be empty for policy semantics, got %s", gate.LastDecision)
		}
		if gate.FirstAttemptAgeSeconds != 0 {
			t.Errorf("FirstAttemptAgeSeconds: want 0, got %d", gate.FirstAttemptAgeSeconds)
		}
	})

	t.Run("existing with complete → status=completed, last=prior decision", func(t *testing.T) {
		first := time.Now().Add(-30 * time.Second)
		existing := &WorkflowStep{
			GateCount:       1,
			CompletionCount: 1,
			Decision:        GateDecisionAllow,
			FirstAttemptAt:  &first,
		}
		var gate StepGateContext
		applyRetryContextToGate(&gate, existing, "")
		if gate.GateCount != 2 {
			t.Errorf("GateCount: want 2, got %d", gate.GateCount)
		}
		if gate.PriorCompletionStatus != PriorCompletionStatusCompleted {
			t.Errorf("PriorCompletionStatus: want completed, got %s", gate.PriorCompletionStatus)
		}
		if gate.LastDecision != GateDecisionAllow {
			t.Errorf("LastDecision: want allow, got %s", gate.LastDecision)
		}
		if gate.FirstAttemptAgeSeconds < 20 {
			t.Errorf("FirstAttemptAgeSeconds: want ~30, got %d", gate.FirstAttemptAgeSeconds)
		}
	})

	t.Run("existing without complete → status=gated_not_completed", func(t *testing.T) {
		first := time.Now().Add(-5 * time.Second)
		existing := &WorkflowStep{
			GateCount:      1,
			Decision:       GateDecisionAllow,
			FirstAttemptAt: &first,
		}
		var gate StepGateContext
		applyRetryContextToGate(&gate, existing, "")
		if gate.PriorCompletionStatus != PriorCompletionStatusGatedNotCompleted {
			t.Errorf("PriorCompletionStatus: want gated_not_completed, got %s", gate.PriorCompletionStatus)
		}
	})

	t.Run("existing key takes precedence over supplied", func(t *testing.T) {
		stored := "K-original"
		existing := &WorkflowStep{
			GateCount:      1,
			IdempotencyKey: &stored,
			Decision:       GateDecisionAllow,
		}
		var gate StepGateContext
		applyRetryContextToGate(&gate, existing, "K-new")
		if gate.IdempotencyKey != stored {
			t.Errorf("IdempotencyKey should prefer stored: want %q, got %q", stored, gate.IdempotencyKey)
		}
	})
}

// TestBuildRetryContext_PriorCompletionStatus_AllBranches exercises every
// branch of the enum derivation in buildRetryContext, matching
// applyRetryContextToGate's semantics.
func TestBuildRetryContext_PriorCompletionStatus_AllBranches(t *testing.T) {
	tests := []struct {
		name        string
		gateCount   int
		completeCnt int
		want        PriorCompletionStatus
		wantAvail   bool
	}{
		{"first call", 1, 0, PriorCompletionStatusNone, false},
		{"retry post-complete", 2, 1, PriorCompletionStatusCompleted, true},
		{"retry with no complete", 2, 0, PriorCompletionStatusGatedNotCompleted, false},
		{"many retries post-complete", 7, 1, PriorCompletionStatusCompleted, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			step := &WorkflowStep{
				GateCount:       tc.gateCount,
				CompletionCount: tc.completeCnt,
				Decision:        GateDecisionAllow,
			}
			rc := buildRetryContext(step, false)
			if rc.PriorCompletionStatus != tc.want {
				t.Errorf("PriorCompletionStatus: want %s, got %s", tc.want, rc.PriorCompletionStatus)
			}
			if rc.PriorOutputAvailable != tc.wantAvail {
				t.Errorf("PriorOutputAvailable: want %v, got %v", tc.wantAvail, rc.PriorOutputAvailable)
			}
		})
	}
}

// --- Test helpers ---

// switchableEvaluator returns whatever decision `current` is set to at call
// time; used to simulate policy decisions that change between gate calls.
type switchableEvaluator struct {
	current GateDecision
}

func (e *switchableEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:  e.current,
		Reason:    fmt.Sprintf("switchable:%s", e.current),
		PolicyIDs: []string{"switchable-policy"},
		PoliciesEvaluated: []PolicyMatch{{
			PolicyID: "switchable-policy", PolicyName: "Switchable", Action: string(e.current),
		}},
	}
}

// captureAuditLogger accumulates every WorkflowAuditEntry so tests can assert
// on metadata (e.g. idempotency_key recorded on step_gate + step_completed).
type captureAuditLogger struct {
	entries []*WorkflowAuditEntry
}

func (c *captureAuditLogger) LogWorkflowOperation(ctx context.Context, entry *WorkflowAuditEntry) {
	cp := *entry
	c.entries = append(c.entries, &cp)
}
