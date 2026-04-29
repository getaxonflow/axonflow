// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Go SDK example for Issue #1673 Phase 1 (retry_context) + Phase 2
// (idempotency_key). Exercises the full feature set end-to-end through the
// SDK against a running enterprise stack.
//
// Usage:
//   source /tmp/axonflow-e2e-env.sh
//   export AXONFLOW_BASE_URL=http://localhost:8080
//   go run main.go

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

func main() {
	endpoint := envOrDefault("AXONFLOW_BASE_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "demo")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	banner("Act 1 — retry_context (Go SDK)")
	act1(client)

	banner("Act 2 — idempotency_key (Go SDK)")
	act2(client)

	banner("All assertions passed ✔")
}

func act1(c *axonflow.AxonFlowClient) {
	wf, err := c.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "go-sdk-retry-context",
	})
	must(err, "create workflow")
	fmt.Printf("workflow: %s\n", wf.WorkflowID)

	// 1) First gate — first-call invariants
	resp, err := c.StepGate(wf.WorkflowID, "step-1", axonflow.StepGateRequest{
		StepName: "first-step",
		StepType: axonflow.StepTypeToolCall,
	})
	must(err, "first gate")
	assertEqInt("first gate_count", 1, resp.RetryContext.GateCount)
	assertEqInt("first completion_count", 0, resp.RetryContext.CompletionCount)
	assertEqStr("first prior_completion_status", "none", string(resp.RetryContext.PriorCompletionStatus))
	assertTrue("first !PriorOutputAvailable", !resp.RetryContext.PriorOutputAvailable)
	assertEqStr("first last_decision (first-call invariant)", string(resp.Decision), string(resp.RetryContext.LastDecision))
	assertTrue("first FirstAttemptAt == LastAttemptAt", resp.RetryContext.FirstAttemptAt.Equal(resp.RetryContext.LastAttemptAt))
	fmt.Println("  first gate invariants ✔")

	// 2) Complete, then re-gate (cached path)
	out := map[string]interface{}{"transfer_id": "TXN-go-1", "amount": 500.0}
	must(c.MarkStepCompleted(wf.WorkflowID, "step-1", &axonflow.MarkStepCompletedRequest{Output: out}), "complete")
	resp, err = c.StepGate(wf.WorkflowID, "step-1", axonflow.StepGateRequest{StepType: axonflow.StepTypeToolCall})
	must(err, "re-gate post-complete")
	assertEqInt("re-gate post-complete gate_count", 2, resp.RetryContext.GateCount)
	assertEqInt("re-gate post-complete completion_count", 1, resp.RetryContext.CompletionCount)
	assertEqStr("re-gate post-complete prior_completion_status", "completed", string(resp.RetryContext.PriorCompletionStatus))
	assertTrue("re-gate post-complete PriorOutputAvailable", resp.RetryContext.PriorOutputAvailable)
	assertTrue("re-gate post-complete PriorOutput omitted by default", resp.RetryContext.PriorOutput == nil)
	assertTrue("re-gate post-complete Cached==true", resp.Cached)
	fmt.Println("  re-gate post-complete ✔")

	// 3) Gate on step-2 without completion (agent crash simulation)
	_, err = c.StepGate(wf.WorkflowID, "step-2", axonflow.StepGateRequest{
		StepName: "second-step", StepType: axonflow.StepTypeToolCall,
	})
	must(err, "step-2 first gate")
	resp, err = c.StepGate(wf.WorkflowID, "step-2", axonflow.StepGateRequest{StepType: axonflow.StepTypeToolCall})
	must(err, "step-2 re-gate")
	assertEqStr("gated_not_completed status", "gated_not_completed", string(resp.RetryContext.PriorCompletionStatus))
	assertEqInt("gated_not_completed completion_count", 0, resp.RetryContext.CompletionCount)
	fmt.Println("  gated_not_completed ✔")

	// 4) include_prior_output=true recovers the payload
	resp, err = c.StepGateWithOptions(wf.WorkflowID, "step-1",
		axonflow.StepGateRequest{StepType: axonflow.StepTypeToolCall},
		axonflow.StepGateOptions{IncludePriorOutput: true},
	)
	must(err, "re-gate with include_prior_output")
	assertTrue("PriorOutput populated", resp.RetryContext.PriorOutput != nil)
	assertEqStr("PriorOutput[transfer_id]", "TXN-go-1", fmt.Sprint(resp.RetryContext.PriorOutput["transfer_id"]))
	fmt.Println("  prior_output recovery ✔")
}

func act2(c *axonflow.AxonFlowClient) {
	wf, err := c.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "go-sdk-idempotency-key",
	})
	must(err, "create workflow")
	fmt.Printf("workflow: %s\n", wf.WorkflowID)

	originalKey := "payment:wire:go-sdk-invoice-1"

	// 5) Gate with key — retry_context.idempotency_key echoes
	resp, err := c.StepGate(wf.WorkflowID, "step-1", axonflow.StepGateRequest{
		StepName: "wire", StepType: axonflow.StepTypeToolCall,
		IdempotencyKey: originalKey,
	})
	must(err, "gate 1 with key")
	assertEqStr("retry_context.idempotency_key echo", originalKey, resp.RetryContext.IdempotencyKey)
	fmt.Println("  key round-trip ✔")

	// 6) Re-gate with different key → IdempotencyKeyMismatchError
	_, err = c.StepGate(wf.WorkflowID, "step-1", axonflow.StepGateRequest{
		StepType: axonflow.StepTypeToolCall, IdempotencyKey: "payment:wire:different-2",
	})
	if err == nil {
		fail("expected IdempotencyKeyMismatchError on gate with different key")
	}
	var mismatch *axonflow.IdempotencyKeyMismatchError
	if !errors.As(err, &mismatch) {
		fail(fmt.Sprintf("expected *IdempotencyKeyMismatchError, got %T: %v", err, err))
	}
	assertEqStr("mismatch expected_key", originalKey, mismatch.ExpectedIdempotencyKey)
	assertEqStr("mismatch received_key", "payment:wire:different-2", mismatch.ReceivedIdempotencyKey)
	assertTrue("mismatch workflow_id populated", strings.HasPrefix(mismatch.WorkflowID, "wf_"))
	assertEqStr("mismatch step_id", "step-1", mismatch.StepID)
	fmt.Println("  typed 409 error ✔")

	// 7) Complete with matching key → success
	must(c.MarkStepCompleted(wf.WorkflowID, "step-1", &axonflow.MarkStepCompletedRequest{
		Output:         map[string]interface{}{"transfer_id": "TXN-K1"},
		IdempotencyKey: originalKey,
	}), "complete with matching key")
	fmt.Println("  complete with matching key ✔")
}

// --- helpers ---

func envOrDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fail("missing env: " + k)
	}
	return v
}

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func must(err error, label string) {
	if err != nil {
		fail(label + ": " + err.Error())
	}
}

func assertTrue(label string, cond bool) {
	if !cond {
		fail("assertion failed: " + label)
	}
}

func assertEqStr(label, want, got string) {
	if want != got {
		fail(fmt.Sprintf("%s: want %q, got %q", label, want, got))
	}
}

func assertEqInt(label string, want, got int) {
	if want != got {
		fail(fmt.Sprintf("%s: want %d, got %d", label, want, got))
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "FAIL: "+msg)
	os.Exit(1)
}

func banner(s string) {
	fmt.Println()
	fmt.Println("━━━", s, "━━━")
}
